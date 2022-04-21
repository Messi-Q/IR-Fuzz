#pragma once
#include <libdevcore/CommonIO.h>
#include <libevm/LegacyVM.h>
#include <iostream>

using namespace dev;
using namespace eth;
using namespace std;

const uint8_t GASLESS = 0;
const uint8_t UNCHECKED_CALL = 1;
const uint8_t TIME_DEPENDENCY = 2;
const uint8_t NUMBER_DEPENDENCY = 3;
const uint8_t DELEGATE_CALL = 4;
const uint8_t REENTRANCY = 5;
const uint8_t FREEZING = 6;
const uint8_t OVERFLOW = 7;
const uint8_t UNDERFLOW = 8;
const uint8_t UNEXPECTED_ETH = 9;
const uint8_t TOTAL = 10;

struct OpcodePayload
{
    u256 wei = 0;
    // u256 gas = 0;
    u256 pc = 0;
    Instruction inst;
    bytes data;
    Address caller;
    Address callee;
    bool isOverflow = false;
    bool isUnderflow = false;
    bool noOnlyOwner = false;
    bool has0Condition = false;
    bool isGasless = false;
    bool isReallyFlow = false;
    bool isChecked = true;
};

struct OpcodeContext
{
    u256 level;
    OpcodePayload payload;
    OpcodeContext(u256 _level, OpcodePayload _payload) : level(_level), payload(_payload) {}
};

using SingleFunction = vector<OpcodeContext>;
using MultipleFunction = vector<SingleFunction>;
