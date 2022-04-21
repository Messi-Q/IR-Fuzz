#pragma once
#include "Common.h"
#include "ContractABI.h"
#include "TargetContainerResult.h"
#include "TargetProgram.h"
#include "Util.h"
#include <liboracle/OracleFactory.h>
#include <map>
#include <vector>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer
{
struct RecordParam
{
    u64 lastpc = 0;
    bool isDeployment = false;
};
class TargetExecutive
{
    TargetProgram* program;
    OracleFactory* oracleFactory;
    bytes code;

public:
    Address addr;
    ContractABI ca;
    TargetExecutive(OracleFactory* oracleFactory, TargetProgram* program, Address addr,
        ContractABI ca, bytes code)
    {
        this->code = code;
        this->ca = ca;
        this->addr = addr;
        this->program = program;
        this->oracleFactory = oracleFactory;
    }
    TargetExecutive() {}
    // TargetContainerResult exec(bytes data, bool isSplice,
    //     const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
    //         unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
    //         unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
    //         unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>>& valids,
    //     bool is_prefuzz);
    TargetContainerResult exec(bytes data, bool isSplice,
        const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
            unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
            unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
            unordered_set<uint64_t>>& valids, bool is_prefuzz);
    void deploy(bytes data, OnOpFunc onOp);
};
}  // namespace fuzzer
