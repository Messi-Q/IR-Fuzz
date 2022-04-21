#pragma once
#include "Common.h"
#include <map>
#include <vector>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer
{
struct TargetContainerResult
{
    TargetContainerResult() {}
    TargetContainerResult(unordered_set<string> tracebits, unordered_map<string, u256> predicates,
        unordered_map<string, vector<int>> prefix_map, unordered_map<string, int> reached_branch,
        unordered_set<string> uniqExceptions, string cksum, string current_testcase);
    

    /* Contains execution paths */
    unordered_set<string> tracebits;
    /* Save predicates */
    unordered_map<string, u256> predicates;
    /* Execution branch msg with their prefix list */
    unordered_map<string, vector<int>> prefix_map;
    /* record reached branch */
    unordered_map<string, int> reached_branch;
    /* Exception path */
    unordered_set<string> uniqExceptions;
    /* Contains checksum of tracebits */
    string cksum;
    /* Current testcase, including func names, para, account */
    string current_testcase;
};
}  // namespace fuzzer
