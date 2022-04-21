#include "BytecodeBranch.h"
#include "Logger.h"
#include "Util.h"

namespace fuzzer
{
BytecodeBranch::BytecodeBranch(const ContractInfo& contractInfo, bool is_prefuzz)
{
    auto deploymentBin =
        contractInfo.bin.substr(0, contractInfo.bin.size() - contractInfo.binRuntime.size());
    auto progInfo = {
        make_tuple(fromHex(deploymentBin), contractInfo.srcmap, false),
        make_tuple(fromHex(contractInfo.binRuntime), contractInfo.srcmapRuntime, true),
    };
    // JUMPI inside constant function
    vector<pair<uint64_t, uint64_t>> constantJumpis;
    for (auto it : contractInfo.constantFunctionSrcmap)
    {
        auto elements = splitString(it, ':');
        constantJumpis.push_back(make_pair(stoi(elements[0]), stoi(elements[1])));
    }
    for (auto progIt : progInfo)
    {
        auto isRuntime = get<2>(progIt);
        auto opcodes = decodeBytecode(get<0>(progIt));
        if(!isRuntime){
           deploymentOpcodes = decodeBytecode(get<0>(progIt));
        }{
           runtimeOpcodes = decodeBytecode(get<0>(progIt));
        }
        auto decompressedSourcemap = decompressSourcemap(get<1>(progIt));
        // offset - len - pc
        vector<tuple<uint64_t, uint64_t, uint64_t>> candidates;
        //vector<string> snippets;
        bool inOnlyOwnerFunction;
        // Find: if (x > 0 && x < 1000)
        for (uint64_t i = 0; i < decompressedSourcemap.size() && i < opcodes.size(); i++)
        {
            if (!is_prefuzz)
            {
                /*find validTimetamps*/
                if (get<1>(opcodes[i]) == Instruction::TIMESTAMP)
                {
                    auto offset = decompressedSourcemap[i][0];
                    auto len = decompressedSourcemap[i][1];
                    auto snippet = contractInfo.source.substr(offset, len);
                    if (snippet.find("timestamp") != string::npos || snippet.find("now") != string::npos)
                    {
                        // Logger::info("------------Tsnippet---------");
                        // Logger::info(snippet);
                        // Logger::info(to_string(get<0>(opcodes[i])));
                        if (isRuntime)
                            runtimeTimestamps.insert(get<0>(opcodes[i]));
                        else
                            deploymentTimestamps.insert(get<0>(opcodes[i]));
                    }
                }
                /* find validBlockNum */
                if (get<1>(opcodes[i]) == Instruction::NUMBER)
                {
                    auto offest = decompressedSourcemap[i][0];
                    auto len = decompressedSourcemap[i][1];
                    // auto snippet = contractInfo.source.substr(offest, len);
                    // Logger::info("------------Bsnippet---------");
                    // Logger::info(snippet);
                    // Logger::info(to_string(get<0>(opcodes[i])));
                    if (isRuntime)
                        runtimeBlockNums.insert(get<0>(opcodes[i]));
                    else
                        deploymentBlockNums.insert(get<0>(opcodes[i]));
                }

                /* if in function */
                if (get<1>(opcodes[i]) == Instruction::CALLDATALOAD ||
                    get<1>(opcodes[i]) == Instruction::CALLDATACOPY)
                {
                    auto offset = decompressedSourcemap[i][0];
                    auto len = decompressedSourcemap[i][1];
                    auto snippet = contractInfo.source.substr(offset, len);
                    if (boost::starts_with(snippet, "function"))
                    {
                        // Logger::info("------------infunction snippet---------");
                        // Logger::info(snippet);
                        // Logger::info(to_string(get<0>(opcodes[i])));
                        // Logger::info("------------infunction snippet end---------");
                        boost::algorithm::to_lower(snippet);
                        inOnlyOwnerFunction = false;  //                in a new function
                        // cout << "new function!" << endl;
                        if (snippet.find("onlyowner") != string::npos)
                        {
                            // Logger::info("------------onlyowner func snippet---------");
                            // Logger::info(snippet);
                            // Logger::info(to_string(get<0>(opcodes[i])));
                            // Logger::info("------------onlyowner func snippet end---------");
                            inOnlyOwnerFunction = true;
                            // cout << "only owner!" << endl;
                        }
                    }
                }
                /* find validDelegateCall */
                if (get<1>(opcodes[i]) == Instruction::DELEGATECALL)
                {
                    auto offset = decompressedSourcemap[i][0];
                    auto len = decompressedSourcemap[i][1];
                    auto snippet = contractInfo.source.substr(offset, len);
                    // cout << "DELEGATECALL" << endl;
                    if (snippet.find("delegatecall") != string::npos)
                    {
                        // Logger::info("------------delegatecall snippet---------");
                        // Logger::info(snippet);
                        // Logger::info(to_string(get<0>(opcodes[i])));
                        // Logger::info("------------delegatecall snippet end---------");
                        if (isRuntime)
                        {
                            runtimeDelegateCalls.insert(get<0>(opcodes[i]));
                            if (!inOnlyOwnerFunction)
                                runtimeNownerDelegateCalls.insert(get<0>(opcodes[i]));
                        }
                    }
                }
            }

            if (get<1>(opcodes[i]) == Instruction::JUMPI)
            {
                auto offset = decompressedSourcemap[i][0];
                auto len = decompressedSourcemap[i][1];
                auto snippet = contractInfo.source.substr(offset, len);
                if (boost::starts_with(snippet, "if") || boost::starts_with(snippet, "while") ||
                    boost::starts_with(snippet, "for") || boost::starts_with(snippet, "require") ||
                    boost::starts_with(snippet, "assert"))
                {
                    //snippets.insert(snippet);
                    //cout<<snippet<<endl;
                    Logger::info("----");
                    for (auto candidate : candidates)
                    {
                        if (get<0>(candidate) > offset &&
                            get<0>(candidate) + get<1>(candidate) < offset + len)
                        {
                            auto candidateSnippet =
                                contractInfo.source.substr(get<0>(candidate), get<1>(candidate));
                            auto numConstant = count_if(constantJumpis.begin(),
                                constantJumpis.end(), [&](const pair<uint64_t, uint64_t>& j) {
                                    return get<0>(candidate) >= get<0>(j) &&
                                           get<0>(candidate) + get<1>(candidate) <=
                                               get<0>(j) + get<1>(j);
                                });
                            if (!numConstant)
                            {
                                Logger::info("Candidate jumpi :");
                                Logger::info(candidateSnippet);
                                if (isRuntime)
                                {
                                    // if (boost::starts_with(snippet, "require") ||
                                    //     boost::starts_with(snippet, "assert"))
                                    //     get<1>(runtimeJumpis).insert(get<2>(candidate));
                                    // else
                                    //     get<0>(runtimeJumpis).insert(get<2>(candidate));
                                    runtimeJumpis.insert(get<2>(candidate));
                                    Logger::info("pc: " + to_string(get<2>(candidate)));
                                    snippets.insert(make_pair(get<2>(candidate), candidateSnippet));
                                }
                                else
                                {
                                    // if (boost::starts_with(snippet, "require") ||
                                    //     boost::starts_with(snippet, "assert"))
                                    //     get<1>(deploymentJumpis).insert(get<2>(candidate));
                                    // else
                                    //     get<0>(deploymentJumpis).insert(get<2>(candidate));
                                    deploymentJumpis.insert(get<2>(candidate));
                                    Logger::info("pc: " + to_string(get<2>(candidate)));
                                    snippets.insert(make_pair(get<2>(candidate), candidateSnippet));
                                }
                            }
                        }
                    }
                    auto numConstant = count_if(constantJumpis.begin(), constantJumpis.end(),
                        [&](const pair<uint64_t, uint64_t>& j) {
                            return offset >= get<0>(j) && offset + len <= get<0>(j) + get<1>(j);
                        });
                    if (!numConstant)
                    {
                        Logger::info("Candidate jumpi :");
                        Logger::info(contractInfo.source.substr(offset, len));
                        if (isRuntime)
                        {
                            // if (boost::starts_with(snippet, "require") ||
                            //     boost::starts_with(snippet, "assert"))
                            //     get<1>(runtimeJumpis).insert(get<0>(opcodes[i]));
                            // else
                            //     get<0>(runtimeJumpis).insert(get<0>(opcodes[i]));
                            runtimeJumpis.insert(get<0>(opcodes[i]));
                            Logger::info("runtime pc: " + to_string(get<0>(opcodes[i])));
                            snippets.insert(make_pair(get<0>(opcodes[i]), snippet));
                        }
                        else
                        {
                            // if (boost::starts_with(snippet, "require") ||
                            //     boost::starts_with(snippet, "assert"))
                            //     get<1>(deploymentJumpis).insert(get<0>(opcodes[i]));
                            // else
                            //     get<0>(deploymentJumpis).insert(get<0>(opcodes[i]));
                            deploymentJumpis.insert(get<0>(opcodes[i]));
                            Logger::info("deployment pc: " + to_string(get<0>(opcodes[i])));
                            snippets.insert(make_pair(get<0>(opcodes[i]), snippet));
                        }
                    }
                    candidates.clear();
                }
                else
                {
                    candidates.push_back(make_tuple(offset, len, get<0>(opcodes[i])));
                }
            }
        }
        /* find ConditionalCall */
        for (uint64_t i = 0; i < decompressedSourcemap.size() && i < opcodes.size(); i++)
        {
          if(get<1>(opcodes[i])==Instruction::CALL||get<1>(opcodes[i])==Instruction::DELEGATECALL){
                    auto offset = decompressedSourcemap[i][0];
                    auto len = decompressedSourcemap[i][1];
                    auto snippet = contractInfo.source.substr(offset, len);
                    if (snippet.find(".send(")!=string::npos||snippet.find(".call(")!=string::npos||
                        snippet.find(".delegatecall(")!=string::npos||snippet.find(".callcode(")!=string::npos||
                        snippet.find(".transfer(")!=string::npos
                    ){
                                if(snippet.find(".transfer(")!=string::npos){
                                if(isRuntime){
                                    runtimeUncheckedCalls.insert(get<0>(opcodes[i]));
                                }else{
                                    deploymentUncheckedCalls.insert(get<0>(opcodes[i]));
                                }
                                }
                        for (auto sp :snippets){
                            if (get<1>(sp).find(snippet)!=string::npos &&
                            (get<1>(sp).find("if")!=string::npos || get<1>(sp).find("while")!=string::npos ||
                                get<1>(sp).find("for")!=string::npos || get<1>(sp).find("require")!=string::npos ||
                                get<1>(sp).find("assert")!=string::npos)){
                                cout<<"-----------"<<endl;
                                cout<<snippet<<endl;
                                cout<<"-----sp------"<<endl;
                                cout<<get<1>(sp)<<endl;
                                if(isRuntime){
                                    runtimeUncheckedCalls.insert(get<0>(opcodes[i]));
                                }else{
                                    deploymentUncheckedCalls.insert(get<0>(opcodes[i]));
                                }
                                break;
                            }
                        }
                    }
                 }
        }
    }
}

vector<pair<uint64_t, Instruction>> BytecodeBranch::decodeBytecode(bytes bytecode)
{
    uint64_t pc = 0;
    vector<pair<uint64_t, Instruction>> instructions;
    while (pc < bytecode.size())
    {
        auto inst = (Instruction)bytecode[pc];
        if (inst >= Instruction::PUSH1 && inst <= Instruction::PUSH32)
        {
            auto jumpNum = bytecode[pc] - (uint64_t)Instruction::PUSH1 + 1;
            // auto payload = bytes(bytecode.begin() + pc + 1, bytecode.begin() + pc + 1 + jumpNum);
            //  // no need
            pc += jumpNum;
        }
        instructions.push_back(make_pair(pc, inst));
        pc++;
    }
    return instructions;
}

// tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
//     unordered_set<uint64_t>>
// BytecodeBranch::findValidJumpis()
// {
//     return make_tuple(get<0>(deploymentJumpis), get<0>(runtimeJumpis), get<1>(deploymentJumpis),
//         get<1>(runtimeJumpis));
// }

pair<unordered_set<uint64_t>, unordered_set<uint64_t>> BytecodeBranch::findValidJumpis() {
    return make_pair(deploymentJumpis, runtimeJumpis);
}

pair<unordered_set<uint64_t>, unordered_set<uint64_t>> BytecodeBranch::findValidBlockNums()
{
    return make_pair(deploymentBlockNums, runtimeBlockNums);
}
pair<unordered_set<uint64_t>, unordered_set<uint64_t>> BytecodeBranch::findValidTimestamps()
{
    return make_pair(deploymentTimestamps, runtimeTimestamps);
}
pair<unordered_set<uint64_t>, unordered_set<uint64_t>> BytecodeBranch::findValidUncheckedCalls()
{
    return make_pair(deploymentUncheckedCalls,runtimeUncheckedCalls);
}
pair<unordered_set<uint64_t>, unordered_set<uint64_t>> BytecodeBranch::findValidDelegateCalls()
{
    return make_pair(runtimeDelegateCalls, runtimeNownerDelegateCalls);
}

vector<vector<uint64_t>> BytecodeBranch::decompressSourcemap(string srcmap)
{
    vector<vector<uint64_t>> components;
    for (auto it : splitString(srcmap, ';'))
    {
        auto sl = splitString(it, ':');
        auto s = sl.size() >= 1 && sl[0] != "" ? stoi(sl[0]) : components[components.size() - 1][0];
        auto l = sl.size() >= 2 && sl[1] != "" ? stoi(sl[1]) : components[components.size() - 1][1];
        components.push_back({s, l});
    }
    return components;
}
}  // namespace fuzzer
