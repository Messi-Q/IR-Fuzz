#pragma once

#include "Common.h"
#include "Fuzzer.h"
#include "Util.h"

namespace fuzzer
{
class BytecodeBranch
{
private:
    // tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> deploymentJumpis;
    // tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> runtimeJumpis;
    unordered_set<uint64_t> deploymentJumpis;
    unordered_set<uint64_t> runtimeJumpis;
    unordered_set<uint64_t> deploymentTimestamps;
    unordered_set<uint64_t> runtimeTimestamps;
    unordered_set<uint64_t> deploymentBlockNums;
    unordered_set<uint64_t> runtimeBlockNums;
    unordered_set<uint64_t> deploymentUncheckedCalls;
    unordered_set<uint64_t> runtimeUncheckedCalls;
    unordered_set<uint64_t> runtimeDelegateCalls;
    unordered_set<uint64_t> runtimeNownerDelegateCalls;

public:
    unordered_map<uint64_t, string> snippets;
    vector<pair<uint64_t, Instruction>> deploymentOpcodes;
    vector<pair<uint64_t, Instruction>> runtimeOpcodes;
    BytecodeBranch(const ContractInfo& contractInfo, bool is_prefuzz);
    // tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
    //     unordered_set<uint64_t>>
    // findValidJumpis();
    pair<unordered_set<uint64_t>, unordered_set<uint64_t>> findValidJumpis();
    pair<unordered_set<uint64_t>, unordered_set<uint64_t>> findValidTimestamps();
    pair<unordered_set<uint64_t>, unordered_set<uint64_t>> findValidBlockNums();
    pair<unordered_set<uint64_t>, unordered_set<uint64_t>> findValidDelegateCalls();
    pair<unordered_set<uint64_t>, unordered_set<uint64_t>> findValidUncheckedCalls();
    static vector<vector<uint64_t>> decompressSourcemap(string srcmap);
    static vector<pair<uint64_t, Instruction>> decodeBytecode(bytes bytecode);
};

}  // namespace fuzzer
