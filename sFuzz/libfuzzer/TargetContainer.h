#pragma once
#include "TargetExecutive.h"
#include <map>
#include <vector>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer
{
class TargetContainer
{
    TargetProgram* program;
    OracleFactory* oracleFactory;
    u160 baseAddress;

public:
    TargetContainer();
    ~TargetContainer();
    pair<vector<uint16_t>, vector<unordered_set<uint16_t>>> analyze()
    {
        return oracleFactory->analyze();
    }
    TargetExecutive loadContract(bytes code, ContractABI ca);
    TargetExecutive loadContract(bytes code, ContractABI ca, Address addr);
    TargetProgram* getProgram();
};
}  // namespace fuzzer
