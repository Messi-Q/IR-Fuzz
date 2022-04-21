#pragma once
#include "Common.h"
#include "TargetContainer.h"

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer
{
struct FuzzItem
{
    bytes data;
    TargetContainerResult res;
    uint64_t fuzzedCount = 0;
    uint64_t depth = 0;
    FuzzItem(bytes _data)
    {
        // cout << "datasize here : " << _data.size() << endl;
        data = _data;
    }
};
using OnMutateFunc = function<FuzzItem(bytes b)>;
}  // namespace fuzzer
