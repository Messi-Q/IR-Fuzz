#include "Fuzzer.h"
#include "BytecodeBranch.h"
#include "ContractABI.h"
#include "Dictionary.h"
#include "Logger.h"
#include "Mutation.h"
#include "Util.h"
#include "jsonxx/include/jsonxx/json.hpp"
#include <fstream>

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;
using namespace jsonxx;
namespace pt = boost::property_tree;

/* Setup virgin byte to 255 */
Fuzzer::Fuzzer(FuzzParam fuzzParam) : fuzzParam(fuzzParam)
{
    fill_n(fuzzStat.stageFinds, 32, 0);  // init fuzzStat.stageFinds
}

/* Detect new exception */
void Fuzzer::updateExceptions(unordered_set<string> exps)
{
    for (auto it : exps)
        uniqExceptions.insert(it);
}

/* Detect new bits by comparing tracebits to virginbits */
void Fuzzer::updateTracebits(unordered_set<string> _tracebits)
{
    for (auto it : _tracebits)
        tracebits.insert(it);
}

void Fuzzer::updatePredicates(unordered_map<string, u256> _pred)
{
    for (auto it : _pred)
    {
        predicates.insert(it.first);
    };
    // Remove covered predicates
    for (auto it = predicates.begin(); it != predicates.end();)
    {
        if (tracebits.count(*it))
        {
            it = predicates.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void Fuzzer::updatePrefixrecorder(unordered_map<string, vector<int>> _pmap)
{
    auto contract = mainContract();
    string name = contract.contractName.substr(10, contract.contractName.find(":") - 14);
    Prefix_msg msg;
    msg.name = name;
    for (auto it : _pmap)
        msg.prefix_map.insert(it);
    prefix_records.push_back(msg);
}

/*write prefix_map into json file*/
void Fuzzer::writePrefix(string bins, int branchSize)
{
    auto contract = mainContract();

    json root, jmap, jarray;
    ifstream rprefix("branch_msg/prefix.json");
    if (rprefix.good())
        rprefix >> root;
    ofstream wprefix("branch_msg/prefix.json");
    string name = contract.contractName;
    name = name.substr(0, name.find(".sol"));
    for (auto premsg : prefix_records)
    {
        for (auto premap : premsg.prefix_map)
            jsonxx::to_json(jmap[premap.first], premap.second);
        jarray["Prefix"] = jmap;
        jarray["Code"] = bins;
        jarray["Coverage"] = (int)((float)tracebits.size() / (float)branchSize * 10000);
        root[premsg.name] = jarray;
    }
    wprefix << std::setw(4) << root << std::endl;
    ofstream wrun_bin(name + ".bin-runtime");
    wrun_bin << bins;
}

void Fuzzer::writeLeaders()
{
    auto contract = mainContract();
    string name = contract.contractName.substr(10, contract.contractName.find(":") - 14);

    json root, jarray;
    ifstream rleaders("branch_msg/leaders.json");
    if (rleaders.good())
        rleaders >> root;
    ofstream wleaders("branch_msg/leaders.json");

    for (auto leader : leaders)
        if (leader.second.comparisonValue == 0)
        {
            jarray[leader.first] = toString(leader.second.item.data);
            root[name] = jarray;
        }
    wleaders << std::setw(4) << root << std::endl;
}

int Fuzzer::readWeight(string contractName)
{
    json root, obj, cov;
    int coverage;
    ifstream rprefix("branch_msg/weight.json");
    if (!rprefix.good())
        exit(1);
    rprefix >> root;

    Energy_msg energy;
    obj = root[contractName]["Weight"];
    cov = root[contractName]["Coverage"];
    if (obj.is_null())
        return 10000;

    coverage = cov.as_int();
    for (auto iter = obj.begin(); iter != obj.end(); iter++)
    {
        energy.branchId = iter.key();
        energy.weight = iter.value().as_int();
        energys.push_back(energy);
    }

    return coverage;
}

void Fuzzer::readLeaders(string contractName)
{
    json root, obj;
    ifstream rleaders("branch_msg/leaders.json");
    if (!rleaders.good())
        exit(1);
    rleaders >> root;

    obj = root[contractName];
    for (auto iter = obj.begin(); iter != obj.end(); iter++)
    {
        FuzzItem item = FuzzItem(fromHex(iter.value().as_string()));
        auto leader = Leader(item, 0);
        leaders.insert(make_pair(iter.key(), leader));
    }
}

ContractInfo Fuzzer::mainContract()
{
    auto contractInfo = fuzzParam.contractInfo;
    auto first = contractInfo.begin();
    auto last = contractInfo.end();
    auto predicate = [](const ContractInfo& c) { return c.isMain; };
    auto it = find_if(first, last, predicate);
    return *it;
}

void Fuzzer::showStats(const Mutation& mutation, const int branchSize)
{
    int i = 0, numLines, stringlen;
    if (fuzzParam.is_prefuzz)
        numLines = 18, stringlen = 20;
    else
        numLines = 24, stringlen = 51;
    if (!fuzzStat.clearScreen)
    {
        for (i = 0; i < numLines; i++)
            cout << endl;
        fuzzStat.clearScreen = true;
    }
    double duration = timer.elapsed();
    double fromLastNewPath = timer.elapsed() - fuzzStat.lastNewPath;
    for (i = 0; i < numLines; i++)
        cout << "\x1b[A";

    auto nowTrying = padStr(mutation.stageName, stringlen);
    auto stageExecProgress = to_string(mutation.stageCur) + "/" + to_string(mutation.stageMax);
    auto stageExecPercentage =
        mutation.stageMax == 0 ?
            to_string(100) :
            to_string((uint64_t)((float)(mutation.stageCur) / mutation.stageMax * 100));
    auto stageExec = padStr(stageExecProgress + " (" + stageExecPercentage + "%)", stringlen);
    auto allExecs = padStr(to_string(fuzzStat.totalExecs), stringlen);
    auto execSpeed = padStr(to_string((int)(fuzzStat.totalExecs / duration)), stringlen);
    auto cyclePercentage = (uint64_t)((float)(fuzzStat.idx + 1) / leaders.size() * 100);
    auto cycleProgress =
        padStr(to_string(fuzzStat.idx + 1) + " (" + to_string(cyclePercentage) + "%)", stringlen);

    auto cycleDone = padStr(to_string(fuzzStat.queueCycle), 15);
    auto totalBranches = branchSize;
    auto numBranches = padStr(to_string(totalBranches), 15);
    auto coverage = padStr(
        to_string((uint64_t)((float)tracebits.size() / (float)totalBranches * 100)) + "%", 15);

    auto flip1 = to_string(fuzzStat.stageFinds[STAGE_FLIP1]) + "/" +
                 to_string(mutation.stageCycles[STAGE_FLIP1]);
    auto flip2 = to_string(fuzzStat.stageFinds[STAGE_FLIP2]) + "/" +
                 to_string(mutation.stageCycles[STAGE_FLIP2]);
    auto flip4 = to_string(fuzzStat.stageFinds[STAGE_FLIP4]) + "/" +
                 to_string(mutation.stageCycles[STAGE_FLIP4]);
    auto bitflip = padStr(flip1 + ", " + flip2 + ", " + flip4, 30);
    auto byte1 = to_string(fuzzStat.stageFinds[STAGE_FLIP8]) + "/" +
                 to_string(mutation.stageCycles[STAGE_FLIP8]);
    auto byte2 = to_string(fuzzStat.stageFinds[STAGE_FLIP16]) + "/" +
                 to_string(mutation.stageCycles[STAGE_FLIP16]);
    auto byte4 = to_string(fuzzStat.stageFinds[STAGE_FLIP32]) + "/" +
                 to_string(mutation.stageCycles[STAGE_FLIP32]);
    auto byteflip = padStr(byte1 + ", " + byte2 + ", " + byte4, 30);
    auto arith1 = to_string(fuzzStat.stageFinds[STAGE_ARITH8]) + "/" +
                  to_string(mutation.stageCycles[STAGE_ARITH8]);
    auto arith2 = to_string(fuzzStat.stageFinds[STAGE_ARITH16]) + "/" +
                  to_string(mutation.stageCycles[STAGE_ARITH16]);
    auto arith4 = to_string(fuzzStat.stageFinds[STAGE_ARITH32]) + "/" +
                  to_string(mutation.stageCycles[STAGE_ARITH32]);
    auto arithmetic = padStr(arith1 + ", " + arith2 + ", " + arith4, 30);
    auto int1 = to_string(fuzzStat.stageFinds[STAGE_INTEREST8]) + "/" +
                to_string(mutation.stageCycles[STAGE_INTEREST8]);
    auto int2 = to_string(fuzzStat.stageFinds[STAGE_INTEREST16]) + "/" +
                to_string(mutation.stageCycles[STAGE_INTEREST16]);
    auto int4 = to_string(fuzzStat.stageFinds[STAGE_INTEREST32]) + "/" +
                to_string(mutation.stageCycles[STAGE_INTEREST32]);
    auto knownInts = padStr(int1 + ", " + int2 + ", " + int4, 30);
    auto addrDict1 = to_string(fuzzStat.stageFinds[STAGE_EXTRAS_AO]) + "/" +
                     to_string(mutation.stageCycles[STAGE_EXTRAS_AO]);
    auto dict1 = to_string(fuzzStat.stageFinds[STAGE_EXTRAS_UO]) + "/" +
                 to_string(mutation.stageCycles[STAGE_EXTRAS_UO]);
    auto dictionary = padStr(dict1 + ", " + addrDict1, 30);
    auto hav1 = to_string(fuzzStat.stageFinds[STAGE_HAVOC]) + "/" +
                to_string(mutation.stageCycles[STAGE_HAVOC]);
    auto havoc = padStr(hav1, 30);

    auto pending = padStr(to_string(leaders.size() - fuzzStat.idx - 1), 5);
    auto fav = count_if(leaders.begin(), leaders.end(),
        [](const pair<string, Leader>& p) { return !p.second.item.fuzzedCount; });
    auto pendingFav = padStr(to_string(fav), 5);
    auto maxdepthStr = padStr(to_string(fuzzStat.maxdepth), 5);
    auto exceptionCount = padStr(to_string(uniqExceptions.size()), 5);
    auto predicateSize = padStr(to_string(predicates.size()), 5);

    auto contract = mainContract();
    // auto toResult = [](bool val) { return val ? "found" : "none "; };

    if (fuzzParam.is_prefuzz)
        printf(cGRN Bold "%sIR-Fuzz branch seaching (%s)" cRST "\n", padStr("", 10).c_str(),
            contract.contractName.substr(10, contract.contractName.find(":") - 14).c_str());
    else
        printf(cGRN Bold "%sIR-Fuzz vulernability detecting (%s)" cRST "\n", padStr("", 10).c_str(),
            contract.contractName.substr(10, contract.contractName.find(":") - 14).c_str());
    printf(bTL bV5 cGRN " processing time " cRST bV20 bV20 bV5 bV2 bV2 bV5 bV bTR "\n");
    printf(bH "      run time : %s " bH "\n", formatDuration(duration).data());
    printf(bH " last new path : %s " bH "\n", formatDuration(fromLastNewPath).data());

    printf(bLTR bV5 cGRN " fuzzing yields " cRST bV5 bV5 bV5 bV2 bV2 bV10 bV bTTR bV cGRN
                         " path geometry " cRST bV2 bV2 bRTR "\n");
    printf(bH "   bit flips : %s" bH "     pending : %s" bH "\n", bitflip.c_str(), pending.c_str());
    printf(bH "  byte flips : %s" bH " pending fav : %s" bH "\n", byteflip.c_str(),
        pendingFav.c_str());
    printf(bH " arithmetics : %s" bH "   max depth : %s" bH "\n", arithmetic.c_str(),
        maxdepthStr.c_str());
    printf(bH "  known ints : %s" bH " uniq except : %s" bH "\n", knownInts.c_str(),
        exceptionCount.c_str());
    printf(bH "  dictionary : %s" bH "  predicates : %s" bH "\n", dictionary.c_str(),
        predicateSize.c_str());
    printf(bH "       havoc : %s" bH "               %s" bH "\n", havoc.c_str(),
        padStr("", 5).c_str());

    if (fuzzParam.is_prefuzz)
    {
        printf(bLTR bV5 cGRN " stage progress " cRST bV5 bV10 bV2 bV bTTR bV10 bV bBTR bV cGRN
                             " overall results " cRST bV2 bRTR "\n");
        printf(bH "  now trying : %s" bH " cycles done : %s" bH "\n", nowTrying.c_str(),
            cycleDone.c_str());
        printf(bH " stage execs : %s" bH "    branches : %s" bH "\n", stageExec.c_str(),
            numBranches.c_str());
        printf(bH " total execs : %s" bH "    coverage : %s" bH "\n", allExecs.c_str(),
            coverage.c_str());
        printf(bH "  exec speed : %s" bH "               %s" bH "\n", execSpeed.c_str(),
            padStr("", 15).c_str());
        printf(bH "  cycle prog : %s" bH "               %s" bH "\n", cycleProgress.c_str(),
            padStr("", 15).c_str());
        printf(bBL bV20 bV2 bV20 bV bBTR bV2 bV10 bV20 bV2 bV2 bBR "\n");
    }
    else
    {
        printf(bLTR bV5 cGRN " stage progress " cRST bV bV10 bV5 bV bV2 bV10 bV bBTR bV bV2 bV5 bV5
                bV2 bV2 bV5 bV bRTR "\n");
        printf(bH "  now trying : %s" bH "\n", nowTrying.c_str());
        printf(bH " stage execs : %s" bH "\n", stageExec.c_str());
        printf(bH " total execs : %s" bH "\n", allExecs.c_str());
        printf(bH "  exec speed : %s" bH "\n", execSpeed.c_str());
        printf(bH "  cycle prog : %s" bH "\n", cycleProgress.c_str());

        printf(bLTR bV5 cGRN " oracle yields " cRST bV bV10 bV5 bV bTTR bV2 bV10 bV2 bV bV2 bV5 bV5
                bV2 bV2 bV5 bV bRTR "\n");
        printf(bH "                 gasless : %5u " bH " dangerous delegatecall : %5u " bH "\n",
            vulnerabilities[GASLESS], vulnerabilities[DELEGATE_CALL]);
        printf(bH "          unchecked call : %5u " bH "         freezing ether : %5u " bH "\n",
            vulnerabilities[UNCHECKED_CALL], vulnerabilities[FREEZING]);
        printf(bH "              reentrancy : %5u " bH "       integer overflow : %5u " bH "\n",
            vulnerabilities[REENTRANCY], vulnerabilities[OVERFLOW]);
        printf(bH "    timestamp dependency : %5u " bH "      integer underflow : %5u " bH "\n",
            vulnerabilities[TIME_DEPENDENCY], vulnerabilities[UNDERFLOW]);
        printf(bH " block number dependency : %5u " bH "       unexpected ether : %5u " bH "\n",
            vulnerabilities[NUMBER_DEPENDENCY], vulnerabilities[UNEXPECTED_ETH]);
        printf(bBL bV20 bV2 bV10 bV5 bV2 bV bBTR bV10 bV5 bV20 bV2 bV2 bBR "\n");
    }
}

void Fuzzer::writeStats(const Mutation& mutation,
    const vector<unordered_set<uint16_t>> vulnerBranch,
    const vector<unordered_set<string>> vulnerCase, int coverage)
{
    auto contract = mainContract();

    json root, vulner;
    vector<json> reports, testCases;
    string name = contract.contractName;
    name = name.substr(0, name.find(".sol"));

    root["totalExecs"] = fuzzStat.totalExecs;
    root["speed"] = (float)fuzzStat.totalExecs / timer.elapsed();
    root["queueCycles"] = fuzzStat.queueCycle;
    root["uniqExceptions"] = uniqExceptions.size();
    root["coverage"] = (float)coverage / 100;

    remove((name + "_report.json").c_str());
    ofstream stats(name + "_report.json");

    if (!fuzzParam.is_prefuzz)
    {
        for (uint8_t i = 0; i < TOTAL; i++)
        {
            json rpt;
            rpt["number"] = vulnerabilities[i];
            string distinction = "";
            for (auto b : vulnerBranch[i])
            {
                string s;
                stringstream hb;
                hb << hex << b;
                // if (i > 3)
                //     cout << dec << (int)i << " : " << hb.str() << endl;
                hb >> s;
                distinction += s + " ";
            }
            if (distinction != "")
                distinction.erase(distinction.end() - 1, distinction.end());
            rpt["instruction distinction"] = distinction;
            testCases.clear();
            uint8_t j = 0;
            for (auto strVul : vulnerCase[i])
            {
                if (j > fuzzParam.case_num - 1)
                    break;
                json tc = json::parse(strVul);
                testCases.push_back(tc);
                j++;
            }
            rpt["test cases"] = testCases;
            reports.push_back(rpt);
        }

        vulner["gasless"] = reports[GASLESS];
        vulner["unchecked call"] = reports[UNCHECKED_CALL];
        vulner["reentrancy"] = reports[REENTRANCY];
        vulner["timestamp dependency"] = reports[TIME_DEPENDENCY];
        vulner["block number dependency"] = reports[NUMBER_DEPENDENCY];
        vulner["dangerous delegatecall"] = reports[DELEGATE_CALL];
        vulner["freezing ether"] = reports[FREEZING];
        vulner["integer overflow"] = reports[OVERFLOW];
        vulner["integer underflow"] = reports[UNDERFLOW];
        vulner["unexpected ether"] = reports[UNEXPECTED_ETH];
        root["vulnerabilities"] = vulner;
    }

    stats << std::setw(4) << root << endl;
    stats.close();
}

/* Save data if interest */
// FuzzItem Fuzzer::saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth,
//     const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
//         unordered_set<uint64_t>>& validJumpis){
FuzzItem Fuzzer::saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth,
    const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis)
{
    unordered_set<uint64_t> epty{};
    tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
        unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
        unordered_set<uint64_t>, unordered_set<uint64_t>>
        eptys(make_tuple(epty, epty, epty, epty, epty, epty, epty, epty));
    auto revisedData = ContractABI::postprocessTestData(data);
    FuzzItem item(revisedData);
    bool isSplice = false;

    if (data0Len && item.data.size() > data0Len)
    {
        bytes usedData(item.data.begin() + data0Len, item.data.end());
        item.data = usedData;
        isSplice = true;
    }
    item.res = te.exec(revisedData, isSplice, tuple_cat(validJumpis, eptys),
        true);  // TargetContainerResult running
    // Logger::debug(Logger::testFormat(item.data));
    // Logger::debug("tracebits");                  //  try to log tracebits route(but it is not)
    // for (auto tracebit : item.res.tracebits)
    // {
    //     Logger::debug(tracebit);
    // }
    fuzzStat.totalExecs++;

    // cout << item.data.size() << endl;

    for (auto tracebit : item.res.tracebits)
    {
        if (!tracebits.count(tracebit))  // new branch
        {
            // Remove leader
            auto lIt = find_if(leaders.begin(), leaders.end(),
                [=](const pair<string, Leader>& p) { return p.first == tracebit; });
            if (lIt != leaders.end())  // may in leader but not in tracebits,
                                       // is a second branch to a covered branch
                leaders.erase(lIt);

            // append new branch
            auto qIt = find_if(
                queues.begin(), queues.end(), [=](const string& s) { return s == tracebit; });
            if (qIt == queues.end())
                queues.push_back(tracebit);

            // Insert leader
            item.depth = depth + 1;
            auto leader =
                Leader(item, 0);  // distance to another branch is set to 0 (this branch is covered)
            leaders.insert(make_pair(tracebit, leader));
            if (depth + 1 > fuzzStat.maxdepth)
                fuzzStat.maxdepth = depth + 1;
            fuzzStat.lastNewPath = timer.elapsed();
            Logger::debug("Cover new branch " + tracebit);
            // Logger::debug(Logger::testFormat(item.data));
        }
    }
    for (auto predicateIt : item.res.predicates)
    {
        auto lIt = find_if(leaders.begin(), leaders.end(),
            [=](const pair<string, Leader>& p) { return p.first == predicateIt.first; });
        if (lIt != leaders.end()                                 // Found Leader (has been covered)
            && lIt->second.comparisonValue > 0                   // Not a covered branch
            && lIt->second.comparisonValue > predicateIt.second  // ComparisonValue is better
                                                                 // (little than lIt)
        )
        {
            // Debug now
            Logger::debug("Found better test case for uncovered branch " + predicateIt.first);
            Logger::debug("prev: " + lIt->second.comparisonValue.str());
            Logger::debug("now : " + predicateIt.second.str());
            // Stop debug
            leaders.erase(lIt);  // Remove leader (the bad test case)

            item.depth = depth + 1;
            auto leader = Leader(item, predicateIt.second);
            leaders.insert(make_pair(predicateIt.first, leader));  // Insert leader
            if (depth + 1 > fuzzStat.maxdepth)
                fuzzStat.maxdepth = depth + 1;
            fuzzStat.lastNewPath = timer.elapsed();
            // Logger::debug(Logger::testFormat(item.data));  // test case
        }
        else if (lIt == leaders.end())  // uncovered of leaders, it has another branch uncovered
        {
            auto leader = Leader(item, predicateIt.second);
            item.depth = depth + 1;

            leaders.insert(make_pair(predicateIt.first, leader));  // Insert leader
            queues.push_back(predicateIt.first);
            if (depth + 1 > fuzzStat.maxdepth)
                fuzzStat.maxdepth = depth + 1;
            fuzzStat.lastNewPath = timer.elapsed();
            // Debug
            Logger::debug("Found new uncovered branch");
            Logger::debug("now: " + predicateIt.second.str());
            // Logger::debug(Logger::testFormat(item.data));
        }
    }
    updateTracebits(item.res.tracebits);
    updatePredicates(item.res.predicates);
    updatePrefixrecorder(item.res.prefix_map);
    return item;
}

// FuzzItem Fuzzer::saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth,
//     const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
//         unordered_set<uint64_t>>& validJumpis,
//     const string branchId, uint64_t fuzzedCount,
//     const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
//         unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
//         unordered_set<uint64_t>, unordered_set<uint64_t>>& validBlkVls)
// {
FuzzItem Fuzzer::saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth,
    const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis,
    const string branchId, uint64_t fuzzedCount,
    const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
        unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
        unordered_set<uint64_t>, unordered_set<uint64_t>>& validBlkVls)
{
    // cout << "enter save if interest!" << endl;
    auto revisedData = ContractABI::postprocessTestData(data);
    FuzzItem item(revisedData);
    bool isSplice = false;

    if (data0Len && item.data.size() > data0Len)
    {
        bytes usedData(item.data.begin() + data0Len, item.data.end());
        item.data = usedData;
        isSplice = true;
    }
    item.res = te.exec(revisedData, isSplice, tuple_cat(validJumpis, validBlkVls), false);

    fuzzStat.totalExecs++;

    if (energys.begin()->branchId == ":")
    {
        energys.begin()->weight--;
        if (fuzzedCount > 16)
        {
            leaders.empty();
            auto leader = Leader(item, 0);
            leaders.insert(make_pair(":", leader));
        }
    }
    else
        for (auto branch : item.res.reached_branch)
        {
            auto lIt = find_if(leaders.begin(), leaders.end(),
                [=](const pair<string, Leader>& p) { return p.first == branch.first; });
            if (lIt == leaders.end())
            {
                auto leader = Leader(item, branch.second);
                leaders.insert(make_pair(branch.first, leader));
                branch_hits.insert(make_pair(branch.first, 0));
            }
            else if (lIt->second.comparisonValue < branch.second ||
                     (lIt->second.comparisonValue == branch.second && fuzzedCount > 16))
            {
                if (lIt->second.comparisonValue == 0)
                    branch_hits.insert(make_pair(branch.first, 0));
                leaders.erase(lIt);
                auto leader = Leader(item, branch.second);  // keep the item with hitcount to
                                                            // current branch
                leaders.insert(make_pair(branch.first, leader));
            }
            /* only modify the energy when hit the branch we need */
            // if (branch.first == branchId)    // not work well
            // {
            auto ergIt = find_if(energys.begin(), energys.end(),
                [=](const Energy_msg& p) { return p.branchId == branch.first; });
            if (ergIt != energys.end())
            {
                auto ergIdx = distance(energys.begin(), ergIt);
                energys[ergIdx].weight = max(0, energys[ergIdx].weight - branch.second);
                // }
                branch_hits[branch.first] += branch.second;
                // Logger::debug("Hit " + branch.first + " : " + to_string(branch.second));
            }
        }

    updateExceptions(item.res.uniqExceptions);
    return item;
}

/* Stop fuzzing */
void Fuzzer::stop()
{
    if (fuzzParam.is_prefuzz)
    {
        Logger::debug("== TEST ==");
        unordered_map<uint64_t, uint64_t> brs;
        for (auto it : leaders)
        {
            auto pc = stoi(splitString(it.first, ':')[0]);
            // Covered
            if (it.second.comparisonValue == 0)
            {
                if (brs.find(pc) == brs.end())
                {
                    brs[pc] = 1;
                }
                else
                {
                    brs[pc] += 1;
                }
            }
            Logger::debug("BR " + it.first);
            Logger::debug("ComparisonValue " + it.second.comparisonValue.str());
            // Logger::debug(Logger::testFormat(it.second.item.data));
        }
        Logger::debug("== END TEST ==");
        for (auto it : snippets)
        {
            if (brs.find(it.first) == brs.end())
            {
                Logger::info(">> Unreachable");
                Logger::info(it.second);
            }
            else
            {
                if (brs[it.first] == 1)
                {
                    Logger::info(">> Haft");
                    Logger::info(it.second);
                }
                else
                {
                    Logger::info(">> Full");
                    Logger::info(it.second);
                }
            }
        }
    }
    else
    {
        Logger::debug("== TEST ==");
        for (auto it : leaders)
        {
            Logger::debug("BR : " + it.first);
            Logger::debug("Max hit counts pre item : " + it.second.comparisonValue.str());
            Logger::debug("Total hit counts : " + to_string(branch_hits[it.first]));
        }
        Logger::debug("== END TEST ==");
    }
    exit(1);
}

/* Start fuzzing */
void Fuzzer::start()
{
    TargetContainer container;
    Dictionary codeDict, addressDict;
    unordered_set<u64> showSet;
    int lib_num = 0;
    for (auto contractInfo : fuzzParam.contractInfo)
    {
        // attacker or victim
        auto isAttacker = contractInfo.contractName.find(fuzzParam.attackerName) != string::npos;
        if (!contractInfo.isMain && !isAttacker)
            continue;
        /* debug bin */
        // if (!contractInfo.isMain)
        //     continue;
        ContractABI ca(contractInfo.abiJson);
        TargetExecutive executive;
        string libName = "";
        // string libBinRuntime = "";
        // u160 libAddr = 0x00;
        // while (fromHex(contractInfo.bin, libName, libAddr).second != "")  // link libraries
        // manually
        // {
        //     libName = fromHex(contractInfo.bin, libName, libAddr).second;
        //     string jsonName =
        //         contractInfo.contractName.substr(0, contractInfo.contractName.find(":")) +
        //         ".json";
        //     // printf("%s\n", jsonName.c_str());
        //     // printf("hex2 : %s\n\n", libPath.c_str());
        //     // break;
        //     pt::ptree root;
        //     pt::read_json(jsonName, root);
        //     string fullLibName = "";
        //     for (auto key : root.get_child("contracts"))
        //     {
        //         if (key.first.find(libName) != string::npos)
        //         {
        //             fullLibName = key.first;
        //             // string libN = libName.substr(key.first.find(":") + 1, 40);
        //             // printf("success: %s\n", libN.c_str());
        //             break;
        //         }
        //     }
        //     if (deployed_lib.find(libName) == deployed_lib.end())
        //     {
        //         if (lib_num > 10)
        //         {
        //             printf("Error: the number of contract libraries should be less than 10!");
        //             exit(0);
        //         }
        //         pt::ptree::path_type binPath("contracts|" + fullLibName + "|bin", '|');
        //         // pt::ptree::path_type binRuntimePath(
        //         //     "contracts|" + fullLibName + "|bin-runtime", '|');
        //         auto lb = fromHex(root.get<string>(binPath));
        //         // auto lbr = fromHex(root.get<string>(binRuntimePath));
        //         executive = container.loadContract(lb, ca, (Address)LIBRARY_ADDRESS[lib_num++]);
        //         executive.deploy(ContractABI::postprocessTestData(ca.randomTestcase()),
        //         EMPTY_ONOP); deployed_lib.insert(make_pair(libName, (u160)executive.addr));
        //         // container.getProgram()->deploy(LIBRARY_ADDRESS[lib_num], lb);
        //         // deployed_lib.insert(make_pair(libName, lib_num++));
        //     }
        //     libAddr = deployed_lib[libName];
        //     // libAddr = LIBRARY_ADDRESS[0];
        //     // libBinRuntime = libName + "_" + ;
        //     // break;
        // }

        // printf("\n%s:\nbin:\n", contractInfo.contractName.c_str());
        // auto bin = fromHex(contractInfo.bin, libName, libAddr).first;
        auto bin = fromHex(contractInfo.bin);
        // printf("\nbinRuntime :\n");
        // auto binRuntime = fromHex(contractInfo.binRuntime, libName, libAddr).first;
        auto binRuntime = fromHex(contractInfo.binRuntime);
        // printf("\n");
        // printf("%s \n", contractInfo.contractName.c_str());
        // // printf("bin:\n%s \n", Logger::testFormat(bin).c_str());
        // printf("bin:\n%s \n", toHex(bin).c_str());
        // continue;
        // Accept only valid jumpis
        executive = container.loadContract(bin, ca);
        if (!contractInfo.isMain)  //                                            deploy attacker
        {
            /* Load Attacker agent contract */
            auto data = ca.randomTestcase();
            auto revisedData = ContractABI::postprocessTestData(data);
            executive.deploy(revisedData, EMPTY_ONOP);
            addressDict.fromAddress(executive.addr.asBytes());
        }
        else if (fuzzParam.is_prefuzz)  //                                     prefuzz main
        {
            codeDict.fromCode(bin);
            auto bytecodeBranch = BytecodeBranch(contractInfo, true);  //              branch
            auto validJumpis = bytecodeBranch.findValidJumpis();
            snippets = bytecodeBranch.snippets;
            // int branchSize = (int)(get<0>(validJumpis).size() + get<1>(validJumpis).size() +
            //                        get<2>(validJumpis).size() + get<3>(validJumpis).size()) *
            //                  2;
            int branchSize = (int)(get<0>(validJumpis).size() + get<1>(validJumpis).size()) * 2;
            if (!branchSize)
            {
                cout << "No valid jumpi" << endl;
                stop();
            }
            data0Len = saveIfInterest(executive, ca.randomTestcase(), 0, validJumpis)
                           .data.size();  // execute first

            int originHitCount = leaders.size();
            /*
                 No branch in runtime
                (may can not reach or
                branched are only in deployment)
            */
            if (!originHitCount)
            {
                cout << "No branch" << endl;
                stop();
            }

            // There are uncovered branches or not
            auto fi = [&](const pair<string, Leader>& p) { return p.second.comparisonValue != 0; };
            auto numUncoveredBranches = count_if(leaders.begin(), leaders.end(), fi);
            if (!numUncoveredBranches)
            {
                auto curItem = (*leaders.begin()).second.item;
                Mutation mutation(curItem, make_tuple(codeDict, addressDict));
                showStats(mutation, branchSize);
                stop();
            }

            // Jump to fuzz loop
            while (true)
            {
                auto leaderIt = leaders.find(queues[fuzzStat.idx]);
                auto curItem = leaderIt->second.item;
                auto comparisonValue = leaderIt->second.comparisonValue;
                if (comparisonValue != 0)
                {
                    Logger::debug(" == Leader ==");
                    Logger::debug("Branch \t\t\t\t " + leaderIt->first);
                    Logger::debug("Comp \t\t\t\t " + comparisonValue.str());
                    Logger::debug("Fuzzed \t\t\t\t " + to_string(curItem.fuzzedCount));
                    // Logger::debug(Logger::testFormat(curItem.data));
                }
                Mutation mutation(curItem, make_tuple(codeDict, addressDict));

                auto save = [&](bytes data) {  //           using save to control execute on
                                               //           specified branch
                    auto item = saveIfInterest(executive, data, curItem.depth,
                        validJumpis);  //                                  execute again
                    /* Show every one second */
                    u64 duration = timer.elapsed();
                    if (!showSet.count(duration))
                    {
                        showSet.insert(duration);
                        switch (fuzzParam.reporter)
                        {
                        case TERMINAL: {
                            showStats(mutation, branchSize);
                            break;
                        }
                        case BOTH: {
                            showStats(mutation, branchSize);
                            break;
                        }
                        }
                    }

                    /* Stop program */
                    /*1.  time limit exceed 2. fuzzing too slow 3. find all branch*/
                    u64 speed = (u64)(fuzzStat.totalExecs / timer.elapsed());
                    if ((timer.elapsed() - fuzzStat.lastNewPath > fuzzParam.duration &&
                            fuzzStat.queueCycle) ||
                        speed <= 10 || !predicates.size())
                    {
                        switch (fuzzParam.reporter)
                        {
                        case TERMINAL: {
                            showStats(mutation, branchSize);
                            writePrefix(toHex(binRuntime), branchSize);
                            writeLeaders();
                            break;
                        }
                        case JSON: {
                            writePrefix(toHex(binRuntime), branchSize);
                            writeLeaders();
                            break;
                        }
                        case BOTH: {
                            showStats(mutation, branchSize);
                            writePrefix(toHex(binRuntime), branchSize);
                            writeLeaders();
                            break;
                        }
                        }
                        stop();
                    }
                    return item;
                };

                // If it is uncovered branch
                if (comparisonValue != 0)
                {
                    // Haven't fuzzed before
                    if (!curItem.fuzzedCount)
                    {
                        Logger::debug("SingleWalkingBit");
                        mutation.singleWalkingBit(save);
                        fuzzStat.stageFinds[STAGE_FLIP1] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("TwoWalkingBit");
                        mutation.twoWalkingBit(save);
                        fuzzStat.stageFinds[STAGE_FLIP2] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("FourWalkingBit");
                        mutation.fourWalkingBit(save);
                        fuzzStat.stageFinds[STAGE_FLIP4] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("SingleWalkingByte");
                        mutation.singleWalkingByte(save);
                        fuzzStat.stageFinds[STAGE_FLIP8] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("TwoWalkingByte");
                        mutation.twoWalkingByte(save);
                        fuzzStat.stageFinds[STAGE_FLIP16] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("FourWalkingByte");
                        mutation.fourWalkingByte(save);
                        fuzzStat.stageFinds[STAGE_FLIP32] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("havoc");
                        mutation.havoc(save);
                        fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();
                    }
                    else
                    {
                        Logger::debug("havoc");
                        mutation.havoc(save);
                        fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();
                        /*fuzz all second branch in leaders again*/
                        Logger::debug("Splice");
                        vector<FuzzItem> items = {};
                        for (auto it : leaders)
                            items.push_back(it.second.item);
                        if (mutation.splice(items, &executive.ca, save))
                        {
                            // cout << "Splice : true\n" << endl;
                            // Logger::debug("havoc");
                            // mutation.havoc(save);
                            // ca.fds.resize(length);
                            fuzzStat.stageFinds[STAGE_SPLICE] += leaders.size() - originHitCount;
                            originHitCount = leaders.size();
                        }
                    }
                }
                leaderIt->second.item.fuzzedCount += 1;
                fuzzStat.idx = (fuzzStat.idx + 1) % leaders.size();
                if (fuzzStat.idx == 0)
                    fuzzStat.queueCycle++;
                /* avoid always fuzz the same item */
                auto nextldIt = leaders.find(queues[fuzzStat.idx]);
                if (nextldIt == leaderIt && branchSize - tracebits.size() > 1)
                {
                    nextldIt =
                        find_if(leaders.begin(), leaders.end(), [=](const pair<string, Leader>& p) {
                            return (p.second.item.fuzzedCount <
                                       leaderIt->second.item.fuzzedCount) &&
                                   (p.second.comparisonValue > 0);
                        });
                    if (nextldIt != leaders.end())
                        fuzzStat.idx = distance(
                            queues.begin(), find(queues.begin(), queues.end(), nextldIt->first));
                }
            }
        }
        else  //                                                                 main
        {
            codeDict.fromCode(bin);
            auto bytecodeBranch = BytecodeBranch(contractInfo, false);  //              branch
            auto validJumpis = bytecodeBranch.findValidJumpis();
            auto validTimestamps = bytecodeBranch.findValidTimestamps();
            auto validNumbers = bytecodeBranch.findValidBlockNums();
            auto validDelegateCalls = bytecodeBranch.findValidDelegateCalls();
            auto validUncheckedCalls = bytecodeBranch.findValidUncheckedCalls();
            snippets = bytecodeBranch.snippets;
            // int branchSize = (int)(get<0>(validJumpis).size() + get<1>(validJumpis).size() +
            //                        get<2>(validJumpis).size() + get<3>(validJumpis).size()) *
            //                  2;
            int branchSize = (int)(get<0>(validJumpis).size() + get<1>(validJumpis).size()) * 2;
            /* execute for the only branch */
            auto contract = mainContract();
            string name = contract.contractName.substr(10, contract.contractName.find(":") - 14);
            int coverage = readWeight(name);
            if (!branchSize || energys.empty())  // no branch case
            {
                branchSize = 1;

                Energy_msg energy;
                energy.branchId = ":";
                /* set weight */
                energy.weight = 128;
                energys.push_back(energy);

                auto item = saveIfInterest(executive, ca.randomTestcase(), 0, validJumpis, "", 0,
                    tuple_cat(
                        validTimestamps, validNumbers, validDelegateCalls, validUncheckedCalls));

                auto leader = Leader(item, 0);
                leaders.insert(make_pair(":", leader));
            }
            else
                readLeaders(name);

            auto enIt = max_element(energys.begin(), energys.end(),
                [](const Energy_msg& p1, const Energy_msg& p2) { return p1.weight < p2.weight; });
            data0Len = leaders.find(enIt->branchId)->second.item.data.size();
            int remaining_energy;
            int fuzz_num = 0;
            vector<uint16_t> lastVulnerabilities(TOTAL, 0);
            vector<unordered_set<uint16_t>> vulnerBranch(TOTAL, unordered_set<uint16_t>{});
            vector<unordered_set<string>> vulnerCase(TOTAL, unordered_set<string>{});

            while (true)
            {
                auto leaderIt = leaders.find(enIt->branchId);
                if (leaderIt == leaders.end())
                {
                    enIt++;
                    if (enIt == energys.end())
                        enIt = energys.begin();
                    continue;
                }
                auto curItem = leaderIt->second.item;
                static string branch_name =
                    leaderIt->first;  // neccessary, may cause stack overflow without it

                Logger::debug(" == Leader ==");
                Logger::debug("BR \t\t\t\t " + leaderIt->first);
                Logger::debug("Remaing energy \t\t\t\t " + to_string(enIt->weight));
                Logger::debug("Fuzzed \t\t\t\t " + to_string(curItem.fuzzedCount));

                Mutation mutation(curItem, make_tuple(codeDict, addressDict));

                auto save = [&](bytes data) {  //           using save to control execute on
                                               //           specified branch
                    auto item = saveIfInterest(executive, data, curItem.depth, validJumpis,
                        branch_name, leaderIt->second.item.fuzzedCount,
                        tuple_cat(validTimestamps, validNumbers, validDelegateCalls,
                            validUncheckedCalls));  //                                  execute
                                                    //                                  again
                    /*
                        analyze and record vulnerabilities distinction
                        only record contract with branched
                    */
                    auto anlz = container.analyze();
                    vulnerabilities = anlz.first;
                    for (uint8_t i = 0; i < TOTAL; i++)
                    {
                        auto branch_targets = anlz.second[i];
                        for (auto t : branch_targets)
                            vulnerBranch[i].insert(t);
                    }
                    for (uint8_t i = 0; i < TOTAL; i++)
                        if (vulnerabilities[i] > lastVulnerabilities[i])
                            vulnerCase[i].insert(item.res.current_testcase);

                    lastVulnerabilities = vulnerabilities;
                    /* Show every one second */
                    u64 duration = timer.elapsed();
                    if (!showSet.count(duration))
                    {
                        showSet.insert(duration);
                        // if (duration % fuzzParam.analyzingInterval == 0)
                        // {
                        //     vulnerabilities = container.analyze();
                        // }
                        switch (fuzzParam.reporter)
                        {
                        case TERMINAL: {
                            showStats(mutation, branchSize);
                            break;
                        }
                        case BOTH: {
                            showStats(mutation, branchSize);
                            break;
                        }
                        }
                    }

                    /* Stop program */
                    /*1. fuzzing too slow 2. energy drain*/
                    u64 speed = (u64)(fuzzStat.totalExecs / timer.elapsed());
                    remaining_energy = 0;
                    for (auto it : energys)
                        remaining_energy += it.weight;
                    if (speed <= 10 || !remaining_energy || duration > fuzzParam.duration)
                    {
                        // vulnerabilities = container.analyze();
                        switch (fuzzParam.reporter)
                        {
                        case TERMINAL: {
                            showStats(mutation, branchSize);
                            break;
                        }
                        case JSON: {
                            writeStats(mutation, vulnerBranch, vulnerCase, coverage);
                            break;
                        }
                        case BOTH: {
                            showStats(mutation, branchSize);
                            writeStats(mutation, vulnerBranch, vulnerCase, coverage);
                            break;
                        }
                        }
                        stop();
                    }
                    return item;
                };

                /*testing according to weight*/
                if (!curItem.fuzzedCount)
                {
                    Logger::debug("SingleWalkingByte");
                    mutation.singleWalkingByte(save);
                    fuzzStat.stageFinds[STAGE_FLIP8] += leaders.size();

                    Logger::debug("TwoWalkingByte");
                    mutation.twoWalkingByte(save);
                    fuzzStat.stageFinds[STAGE_FLIP16] += leaders.size();

                    Logger::debug("FourWalkingByte");
                    mutation.fourWalkingByte(save);
                    fuzzStat.stageFinds[STAGE_FLIP32] += leaders.size();

                    Logger::debug("SingleInterest");
                    mutation.singleInterest(save);
                    fuzzStat.stageFinds[STAGE_INTEREST8] += leaders.size();

                    Logger::debug("TwoInterest");
                    mutation.twoInterest(save);
                    fuzzStat.stageFinds[STAGE_INTEREST16] += leaders.size();

                    Logger::debug("FourInterest");
                    mutation.fourInterest(save);
                    fuzzStat.stageFinds[STAGE_INTEREST32] += leaders.size();

                    // Logger::debug("overwriteWithDictionary");
                    // mutation.overwriteWithDictionary(save);
                    // fuzzStat.stageFinds[STAGE_EXTRAS_UO] += leaders.size();

                    Logger::debug("overwriteAddress");
                    mutation.overwriteWithAddressDictionary(save);
                    fuzzStat.stageFinds[STAGE_EXTRAS_AO] += leaders.size();

                    Logger::debug("havoc");
                    mutation.havoc(save);
                    fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size();
                }
                else
                {
                    Logger::debug("havoc");
                    mutation.havoc(save);
                    fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size();

                    /*fuzz all second branch in leaders again*/
                    Logger::debug("Splice");
                    vector<FuzzItem> items = {};
                    for (auto it : leaders)
                        items.push_back(it.second.item);
                    if (mutation.splice(items, &executive.ca, save))
                    {
                        // Logger::debug("havoc");
                        // mutation.havoc(save);
                        fuzzStat.stageFinds[STAGE_SPLICE] += leaders.size();
                    }
                }

                leaderIt->second.item.fuzzedCount += 1;
                enIt = max_element(
                    energys.begin(), energys.end(), [](const Energy_msg& p1, const Energy_msg& p2) {
                        return p1.weight < p2.weight;
                    });
                fuzz_num++;
                if (fuzz_num % energys.size() == 1)
                    fuzzStat.queueCycle++;
            }
        }
    }
}
