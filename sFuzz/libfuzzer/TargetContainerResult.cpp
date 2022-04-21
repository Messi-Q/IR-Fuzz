#include "TargetContainerResult.h"

namespace fuzzer
{
TargetContainerResult::TargetContainerResult(unordered_set<string> tracebits,
    unordered_map<string, u256> predicates, unordered_map<string, vector<int>> prefix_map,
    unordered_map<string, int> reached_branch, unordered_set<string> uniqExceptions, string cksum,
    string current_testcase)
{
    this->tracebits = tracebits;
    this->cksum = cksum;
    this->predicates = predicates;
    this->prefix_map = prefix_map;
    this->reached_branch = reached_branch;
    this->uniqExceptions = uniqExceptions;
    this->current_testcase = current_testcase;
}
}  // namespace fuzzer
