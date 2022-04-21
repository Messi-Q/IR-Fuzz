#include "OracleFactory.h"

using namespace dev;
using namespace eth;
using namespace std;

void OracleFactory::initialize()
{
    function.clear();
}

void OracleFactory::finalize()
{
    functions.push_back(function);
    function.clear();
}

void OracleFactory::save(OpcodeContext ctx)
{
    function.push_back(ctx);
}

pair<vector<uint16_t>, vector<unordered_set<uint16_t>>> OracleFactory::analyze()
{
    for (auto function : functions)
    {
        for (uint8_t i = 0; i < TOTAL; i++)
        {
            switch (i)
            {
            case GASLESS: {
                bool gasless = false;
                uint16_t lastpc1 = 0;
                uint16_t lastpc2 = 0;
                for (auto ctx : function)
                {
                    /* traditional gasless oracle */
                    // auto level = ctx.level;
                    // auto inst = ctx.payload.inst;
                    // auto gas = ctx.payload.gas;
                    // auto data = ctx.payload.data;
                    // gasless_send = gasless_send || (level == 1 && inst == Instruction::CALL &&
                    //                                    !data.size() && (gas == 2300 || gas ==
                    //                                    0));
                    if (ctx.payload.isGasless)
                    {
                        gasless = gasless || true;
                        distinctions[i].insert(lastpc2);  // gasless occur after it
                    }
                    lastpc2 = lastpc1;
                    lastpc1 = (uint16_t)ctx.payload.pc;
                }
                if (gasless)
                    vulnerabilities[i]++;
                break;
            }
            case UNCHECKED_CALL: {
                bool unchecked_call = false;
                auto rootCallResponse = function[function.size() - 1];
                bool rootException = rootCallResponse.payload.inst == Instruction::INVALID && !rootCallResponse.level;
                for (auto ctx : function)
                {
                    if ((!rootException && ctx.payload.inst == Instruction::INVALID && ctx.level )||!ctx.payload.isChecked)
                    // if (!rootException && ctx.payload.inst == Instruction::INVALID && ctx.level )
                    {
                        unchecked_call = unchecked_call || true;
                        distinctions[i].insert((uint16_t)ctx.payload.pc);
                    }
                }
                // bool reached_jumpi = false;
                // bool in_condition = false;
                // u256 lastpc = 0;
                // for (auto ctx : function)
                // {
                //     switch (ctx.payload.inst)
                //     {
                //     case Instruction::CALL:
                //     case Instruction::CALLCODE:
                //     case Instruction::DELEGATECALL:
                //     case Instruction::STATICCALL: {
                //         lastpc = ctx.payload.pc;
                //         reached_jumpi = false;
                //     }
                //     default: {
                //         break;
                //     }
                //     }

                //     reached_jumpi = reached_jumpi || ctx.payload.inst == Instruction::JUMPCI;
                //     if (ctx.payload.inst == Instruction::JUMPCI && ctx.payload.pc - lastpc < 11)
                //     {
                //         in_condition = in_condition || true;
                //         distinctions[i].insert((uint16_t)lastpc);
                //     }
                // }
                if (unchecked_call)
                    vulnerabilities[i]++;
                break;
            }
            case TIME_DEPENDENCY: {
                bool has_timestamp = false;
                bool has_sha3 = false;
                bool reached_jumpi = false;
                bool in_condition = false;
                u256 lastpc = 0;
                for (auto ctx : function)
                {
                    // has_transfer = has_transfer || ctx.payload.wei > 0;
                    //                                           only process payable function
                    if (ctx.payload.inst == Instruction::TIMESTAMP)
                    {
                        has_timestamp = has_timestamp || true;
                        lastpc = ctx.payload.pc;
                        reached_jumpi = false;
                    }
                    if (has_timestamp && !reached_jumpi)
                        if (ctx.payload.inst == Instruction::SHA3)
                        {
                            has_sha3 = has_sha3 || true;
                            distinctions[i].insert((uint16_t)lastpc);
                        }
                    reached_jumpi = reached_jumpi || ctx.payload.inst == Instruction::JUMPCI;
                    switch (ctx.payload.inst)
                    {
                    case Instruction::GT:
                    case Instruction::SGT:
                    case Instruction::LT:
                    case Instruction::SLT:
                    case Instruction::EQ: {
                        if (ctx.payload.pc - lastpc < 3)
                            lastpc = ctx.payload.pc;
                        break;
                    }
                    default: {
                        break;
                    }
                    }
                    if (ctx.payload.inst == Instruction::JUMPCI && ctx.payload.pc - lastpc < 9)
                    {
                        in_condition = in_condition || true;
                        distinctions[i].insert((uint16_t)lastpc);
                    }
                }
                if ((has_timestamp && in_condition) || has_sha3)
                    vulnerabilities[i]++;
                break;
            }
            case NUMBER_DEPENDENCY: {
                auto has_number = false;
                auto has_sha3 = false;
                auto reached_jumpi = false;
                auto in_condition = false;
                u256 lastpc = 0;
                for (auto ctx : function)
                {
                    // has_transfer = has_transfer || ctx.payload.wei > 0;
                    if (ctx.payload.inst == Instruction::NUMBER)
                    {
                        has_number = has_number || true;
                        lastpc = ctx.payload.pc;
                        reached_jumpi = false;
                    }
                    /*
                        used as seed of random number
                        we assume using blockhash is safe
                    */
                    if (has_number && !reached_jumpi)
                        if (ctx.payload.inst == Instruction::SHA3)
                        {
                            has_sha3 = has_sha3 || true;
                            distinctions[i].insert((uint16_t)lastpc);
                        }
                    reached_jumpi = reached_jumpi || ctx.payload.inst == Instruction::JUMPCI;
                    switch (ctx.payload.inst)
                    {
                    case Instruction::GT:
                    case Instruction::SGT:
                    case Instruction::LT:
                    case Instruction::SLT:
                    case Instruction::EQ: {
                        if (ctx.payload.pc - lastpc < 3)
                            lastpc = ctx.payload.pc;
                        break;
                    }
                    default: {
                        break;
                    }
                    }
                    if (ctx.payload.inst == Instruction::JUMPCI && ctx.payload.pc - lastpc < 9)
                    {
                        in_condition = in_condition || true;
                        distinctions[i].insert((uint16_t)lastpc);
                    }
                }
                if ((has_number && in_condition) || has_sha3)
                    vulnerabilities[i]++;
                break;
            }
            case DELEGATE_CALL: {
                /*
                     extra delegate call rules are in executive and bytecode branch
                     there will be no DELEGATECALL instruction if
                     1. no .delegatecall() in source code
                     2. no onlyowner modifier in function that invoke delegatecall
                 */
                bool delegate_call = false;
                auto rootCall = function[0];
                auto data = rootCall.payload.data;      // msg.data
                auto caller = rootCall.payload.caller;  // msg.sender
                for (auto ctx : function)
                {
                    if (ctx.payload.inst == Instruction::DELEGATECALL && ctx.payload.noOnlyOwner)
                    {
                        if (data == ctx.payload.data || caller == ctx.payload.callee ||
                            toHex(data).find(toHex(ctx.payload.callee)) != string::npos)
                        {
                            delegate_call = delegate_call || true;
                            distinctions[i].insert((uint16_t)ctx.payload.pc);
                        }
                    }
                }
                if (delegate_call)
                    vulnerabilities[i]++;
                break;
            }
            case REENTRANCY: {
                auto has_loop = false;
                bytes data;
                uint16_t may_reentrancy = 0;
                for (auto ctx : function)
                {
                    // if (ctx.level >= 3 && toHex(ctx.payload.data) == "000000ff")
                    if (ctx.level == 0)
                    {
                        data = ctx.payload.data;  // first possible fallback call data
                        may_reentrancy = (uint16_t)ctx.payload.pc;
                    }
                    // cout<<"caller: "<<ctx.payload.caller<<endl;
                    // cout<<"callee: "<<ctx.payload.callee<<endl;
                    if (ctx.level >= 10 && ctx.payload.caller == (h160)0xf1)  // last fallback call
                    {
                        has_loop = has_loop || true;
                        distinctions[i].insert(may_reentrancy);
                    }
                }
                if (has_loop)
                    vulnerabilities[i]++;
                break;
            }
            case FREEZING: {
                auto has_delegate = false;
                u256 dcpc;
                for (auto ctx : function)
                {
                    freezing_transfer =
                        freezing_transfer ||
                        (ctx.level == 1 && (ctx.payload.inst == Instruction::CALL ||
                                               ctx.payload.inst == Instruction::CALLCODE ||
                                               ctx.payload.inst == Instruction::SUICIDE));
                    // recieve_balance = recieve_balance || ctx.payload.wei > 0;
                    if (ctx.payload.inst == Instruction::DELEGATECALL)
                    {
                        has_delegate = has_delegate || true;
                        dcpc = ctx.payload.pc;
                    }
                }
                if (has_delegate && !freezing_transfer)
                {
                    vulnerabilities[i]++;
                    distinctions[i].insert((uint16_t)dcpc);
                }
                break;
            }
            case UNDERFLOW: {
                bool underflow = false;
                for (auto ctx : function)
                    if (ctx.payload.isUnderflow)
                    {
                        underflow = underflow || true;
                        distinctions[i].insert((uint16_t)ctx.payload.pc);
                    }
                if (underflow)
                    vulnerabilities[i]++;
                break;
            }
            case OVERFLOW: {
                bool overflow = false;
                uint16_t mayoverflow = 0;
                uint8_t overflow_num = 0;
                for (auto ctx : function)
                {
                    if (ctx.payload.isOverflow)
                    {
                        mayoverflow = (uint16_t)ctx.payload.pc;
                        overflow = overflow || true;
                        distinctions[i].insert(mayoverflow);
                        overflow_num++;
                    }
                    // if (overflow)
                    //     switch (ctx.payload.inst)
                    //     {
                    //     case Instruction::GT:
                    //     case Instruction::SGT:
                    //     case Instruction::LT:
                    //     case Instruction::SLT:
                    //     case Instruction::EQ: {
                    //         overflow = overflow && ctx.payload.isReallyFlow;
                    //         if (!overflow)
                    //         {
                    //             distinctions[i].erase(mayoverflow);
                    //             overflow_num--;
                    //         }
                    //     }
                    //     default: {
                    //         break;
                    //     }
                    //     }
                }
                if (overflow_num != 0)
                    vulnerabilities[i]++;
                break;
            }
            case UNEXPECTED_ETH: {
                auto has_balance = false;
                auto reached_jumpi = false;
                auto in_condition = false;
                u256 lastpc = 0;
                for (auto ctx : function)
                {
                    if (ctx.payload.inst == Instruction::BALANCE)
                    {
                        has_balance = has_balance || true;
                        lastpc = ctx.payload.pc;
                        reached_jumpi = false;
                    }
                    reached_jumpi = reached_jumpi || ctx.payload.inst == Instruction::JUMPCI;
                    switch (ctx.payload.inst)
                    {
                    case Instruction::GT:
                    case Instruction::SGT:
                    case Instruction::LT:
                    case Instruction::SLT:
                    case Instruction::EQ: {  // in comparison and both side are not 0
                        if (ctx.payload.pc - lastpc < 3 && !ctx.payload.has0Condition)
                            lastpc = ctx.payload.pc;
                        // in_condition = in_condition || true;
                        break;
                    }
                    default: {
                        break;
                    }
                    }
                    if (ctx.payload.inst == Instruction::JUMPCI && ctx.payload.pc - lastpc < 9)
                    {
                        in_condition = in_condition || true;
                        distinctions[i].insert((uint16_t)lastpc);
                    }
                }
                if (has_balance && in_condition)
                    vulnerabilities[i]++;
                break;
            }
            }
        }
        /* debug executing route */
        // cout << "Fun:" << endl;
        // for (auto ctx : function)
        // {
        //     cout << ctx.payload.pc << " : " << (int)ctx.payload.inst << endl;
        // }
    }
    functions.clear();
    return make_pair(vulnerabilities, distinctions);
}
