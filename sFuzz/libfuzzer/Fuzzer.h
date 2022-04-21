#pragma once
#include "ContractABI.h"
#include "FuzzItem.h"
#include "Mutation.h"
#include "Util.h"
#include <liboracle/Common.h>
#include <iostream>
#include <vector>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer
{
enum FuzzMode
{
    AFL
};
enum Reporter
{
    TERMINAL,
    JSON,
    BOTH
};
struct ContractInfo
{
    string abiJson;
    string bin;
    string binRuntime;
    string contractName;
    string srcmap;
    string srcmapRuntime;
    string source;
    vector<string> constantFunctionSrcmap;
    bool isMain;
};
struct FuzzParam
{
    vector<ContractInfo> contractInfo;
    FuzzMode mode;
    Reporter reporter;
    int duration;
    int case_num;
    int analyzingInterval;
    string attackerName;
    bool is_prefuzz;
};
struct FuzzStat
{
    int idx = 0;
    uint64_t maxdepth = 0;
    bool clearScreen = false;
    int totalExecs = 0;
    int queueCycle = 0;
    int stageFinds[32];
    double lastNewPath = 0;
};
struct Leader
{
    FuzzItem item;
    u256 comparisonValue = 0;
    Leader(FuzzItem _item, u256 _comparisionValue) : item(_item)
    {
        comparisonValue =
            _comparisionValue;  // this value shows the distance to the other branch in prefuzz
                                //            how many times this branch is covered in later fuzzing
    }
};
struct Prefix_msg
{
    unordered_map<string, vector<int>> prefix_map;  // tracebits(branchId), prefix list (plist)
    string name;                                    // ContractName
};
struct Energy_msg
{
    int weight;
    string branchId;
};

class Fuzzer
{
    vector<uint16_t> vulnerabilities;
    vector<string> queues;
    unordered_set<string> tracebits;
    unordered_set<string> predicates;
    vector<Prefix_msg> prefix_records;
    vector<Energy_msg> energys;
    unordered_map<string, int> branch_hits;
    unordered_map<string, u160> deployed_lib;
    unordered_map<string, Leader> leaders;
    unordered_map<uint64_t, string> snippets;
    unordered_set<string> uniqExceptions;
    Timer timer;
    FuzzParam fuzzParam;
    FuzzStat fuzzStat;
    int data0Len = 0;
    void writeStats(const Mutation& mutation, const vector<unordered_set<uint16_t>> vulnerBranch,
        const vector<unordered_set<string>> vulnerCase, int coverage);
    void writePrefix(string bins, int branchSize);
    void writeLeaders();
    int readWeight(string contractName);
    void readLeaders(string contractName);
    ContractInfo mainContract();

public:
    Fuzzer(FuzzParam fuzzParam);
    // FuzzItem saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth,
    //     const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
    //         unordered_set<uint64_t>>& validJumpis);  // prefuzz
    FuzzItem saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth,
     const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis);
    // FuzzItem saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth,
    //     const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
    //         unordered_set<uint64_t>>& validJumpis,
    //     const string branchId, uint64_t fuzzedCount,
    //     const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
    //         unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
    //         unordered_set<uint64_t>, unordered_set<uint64_t>>& validBlkVls);  // fuzzing
     FuzzItem saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth,
        const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis,
        const string branchId, uint64_t fuzzedCount,
        const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
            unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
            unordered_set<uint64_t>, unordered_set<uint64_t>>& validBlkVls);  // fuzzing
    void showStats(const Mutation& mutation, const int branchSize);
    void updateTracebits(unordered_set<string> tracebits);
    void updatePredicates(unordered_map<string, u256> predicates);
    void updatePrefixrecorder(unordered_map<string, vector<int>> prefix_map);
    void updateExceptions(unordered_set<string> uniqExceptions);
    void start();
    void stop();
};
}  // namespace fuzzer
