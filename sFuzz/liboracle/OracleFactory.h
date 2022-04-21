#pragma once
#include "Common.h"
#include <iostream>

using namespace dev;
using namespace eth;
using namespace std;

class OracleFactory
{
    MultipleFunction functions;
    SingleFunction function;
    vector<uint16_t> vulnerabilities;
    vector<unordered_set<uint16_t>> distinctions;
    // bool recieve_balance;
    bool freezing_transfer;

public:
    OracleFactory()
    {
        while (vulnerabilities.size() < TOTAL)
        {
            vulnerabilities.push_back(0);
        }
        distinctions.assign(TOTAL, unordered_set<uint16_t>{});
        // recieve_balance = false;
        freezing_transfer = false;
    }
    void initialize();
    void finalize();
    void save(OpcodeContext ctx);
    pair<vector<uint16_t>, vector<unordered_set<uint16_t>>> analyze();
};
