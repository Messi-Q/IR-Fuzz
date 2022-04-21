#include "TargetExecutive.h"
#include "Logger.h"

namespace fuzzer
{
void TargetExecutive::deploy(bytes data, OnOpFunc onOp)
{
    ca.updateTestData(data);
    program->deploy(addr, bytes{code});
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""), onOp);
}

// TargetContainerResult TargetExecutive::exec(bytes data, bool isSplice,
//     const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
//         unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
//         unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
//         unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>>& valids,
//     bool is_prefuzz)
// {
TargetContainerResult TargetExecutive::exec(bytes data, bool isSplice,
const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
    unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
    unordered_set<uint64_t>, unordered_set<uint64_t>, unordered_set<uint64_t>,
    unordered_set<uint64_t>>& valids,bool is_prefuzz)
{
    /* Save all hit branches to trace_bits */
    Instruction prevInst = Instruction::INVALID;
    RecordParam recordParam;
    u256 lastCompValue = 1;
    u64 jumpDest1 = 0;
    u64 jumpDest2 = 0;
    unordered_set<string> uniqExceptions;
    unordered_set<string> tracebits;
    unordered_map<string, u256> predicates;
    vector<bytes> outputs;

    /* record prefix route */
    unordered_map<string, vector<int>> prefix_map;
    vector<int> pclist;
    // unordered_map<int, int> loop;
    // unordered_map<string, unordered_map<int, int>> loops;
    // u64 last_ppc;
    // int last_jump = 0;
    // int pc_index = 0;
    int last_branch = 0;
    int branch_len = 1;
    bool isReallyFlow = false;
    u512 recordFlow = 0;
    u64 preStep = 0;
    u64 preDataload = 0;
    bool record_pc = true;
    unordered_map<string, vector<FuncDef>> func_map;
    unordered_map<string, int> reached_branch;
    int transactionNum = 0;

    size_t savepoint = program->savepoint();

    /* Decode and call functions */
    ca.updateTestData(data);
    vector<bytes> funcs = ca.encodeFunctions();

    /* Option function before execute current inst */
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint gasCost, bigint gasLeft,
                        VMFace const* _vm, ExtVMFace const* ext) {
        if (isSplice && transactionNum > 0 && transactionNum <= funcs.size() / 2)
            return;
        auto vm = dynamic_cast<LegacyVM const*>(_vm);
        /* Oracle analyze data */
        if (!is_prefuzz)
        {
            switch (inst)
            {
            case Instruction::CALL:
            case Instruction::CALLCODE:
            case Instruction::DELEGATECALL:
            case Instruction::STATICCALL: {  //                     call other function,
                                             //          add the inner function to oracle stack
                if (inst == Instruction::DELEGATECALL)
                {
                    // auto recordable = !recordParam.isDeployment && get<8>(valids).count(pc);
                    auto recordable = !recordParam.isDeployment && get<6>(valids).count(pc);
                    if (!recordable)  // normal delegatecall
                        break;
                }
                vector<u256>::size_type stackSize = vm->stack().size();
                u256 wei = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ?
                               vm->stack()[stackSize - 3] :
                               0;
                auto sizeOffset = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ?
                                      (stackSize - 4) :
                                      (stackSize - 3);
                auto inOff = (uint64_t)vm->stack()[sizeOffset];
                auto inSize = (uint64_t)vm->stack()[sizeOffset - 1];
                auto first = vm->memory().begin();
                OpcodePayload payload;
                payload.caller = ext->myAddress;
                payload.callee = Address((u160)vm->stack()[stackSize - 2]);
                payload.pc = pc;
                // payload.gas = vm->stack()[stackSize - 1];
                payload.wei = wei;
                payload.inst = inst;
                payload.data = bytes(first + inOff, first + inOff + inSize);
                if (inst == Instruction::DELEGATECALL)
                {
                    // auto recordable = !recordParam.isDeployment && get<9>(valids).count(pc);
                    auto recordable = !recordParam.isDeployment && get<7>(valids).count(pc);
                    if (recordable)  // delegatecall without onlyowner modifier
                        payload.noOnlyOwner = true;
                }
                if (inst == Instruction::CALL || inst == Instruction::DELEGATECALL)
                {
                    // auto Ischecked = recordParam.isDeployment && get<10>(valids).count(pc);
                    // Ischecked =
                    //     Ischecked || (!recordParam.isDeployment && get<11>(valids).count(pc));
                    auto isExit = get<0>(valids).count(pc) || get<1>(valids).count(pc)||
                                  get<2>(valids).count(pc) || get<3>(valids).count(pc)||
                                  get<4>(valids).count(pc) || get<5>(valids).count(pc)||
                                  get<6>(valids).count(pc) || get<7>(valids).count(pc)||
                                  get<8>(valids).count(pc) || get<9>(valids).count(pc);
                    if (isExit){
                        auto Ischecked = recordParam.isDeployment && get<8>(valids).count(pc);
                        Ischecked =
                            Ischecked || (!recordParam.isDeployment && get<9>(valids).count(pc));
                        payload.isChecked = Ischecked;
                    }

                    // if(!payload.isChecked){
                    //     cout<<"--------"<<endl;
                    //     cout<<payload.pc<<endl;
                    // }
                }
                oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
                break;
            }
            default: {  //                     only record inst related to bugs
                        //                     other inst not recorded
                // if (pc == 0)
                //     cout << "\n" << endl;

                if (inst == Instruction::CALLDATALOAD)
                    preDataload = pc;

                OpcodePayload payload;
                payload.pc = pc;
                payload.inst = inst;

                if ((uint8_t)prevInst > 0x5f && (uint8_t)prevInst < 0x80 &&
                    recordParam.lastpc != preDataload + 1 &&
                    inst == Instruction::AND)  // normal overflow
                {
                    vector<u256>::size_type stackSize = vm->stack().size();
                    auto pushVul = vm->stack()[stackSize - 1];
                    auto preTrans = vm->stack()[stackSize - 2];
                    if ((pushVul + 1) % 16 == 0)  //                actual type transform
                    {
                        // cout << hex << "push value " << pushVul << " pc " << recordParam.lastpc
                        //      << endl;
                        // cout << dec << "pretrans " << preTrans << endl;
                        // cout << "aftertrans " << (preTrans & pushVul) << endl;
                        // cout << "step : " << step << " prestep : " << preStep << endl;
                        auto afterTrans = preTrans & pushVul;
                        if (preTrans != afterTrans)
                        {
                            // cout << "find unequal trans" << endl;
                            recordFlow = preTrans;
                            payload.isOverflow = true;
                            isReallyFlow = true;
                            payload.isReallyFlow = isReallyFlow;
                            oracleFactory->save(OpcodeContext(ext->depth, payload));
                        }
                    }
                    break;
                }
                if (inst == Instruction::SUICIDE || inst == Instruction::NUMBER ||
                    inst == Instruction::TIMESTAMP || inst == Instruction::INVALID ||
                    inst == Instruction::ADD || inst == Instruction::SUB ||
                    inst == Instruction::SHA3 || inst == Instruction::BALANCE)
                {
                    if (inst == Instruction::TIMESTAMP)
                    {
                        // auto recordable = recordParam.isDeployment && get<4>(valids).count(pc);
                        // recordable =
                        //     recordable || !recordParam.isDeployment && get<5>(valids).count(pc);
                        auto recordable = recordParam.isDeployment && get<2>(valids).count(pc);
                        recordable =
                            recordable || !recordParam.isDeployment && get<3>(valids).count(pc);
                        if (!recordable)
                            break;
                    }
                    if (inst == Instruction::NUMBER)
                    {
                        // auto recordable = recordParam.isDeployment && get<6>(valids).count(pc);
                        // recordable =
                        //     recordable || !recordParam.isDeployment && get<7>(valids).count(pc);
                        auto recordable = recordParam.isDeployment && get<4>(valids).count(pc);
                        recordable =
                            recordable || !recordParam.isDeployment && get<5>(valids).count(pc);
                        if (!recordable)
                            break;
                    }
                    vector<u256>::size_type stackSize = vm->stack().size();
                    if (inst == Instruction::ADD || inst == Instruction::SUB ||
                        inst == Instruction::MUL)  // overflow case
                    {
                        u512 left = vm->stack()[stackSize - 1];
                        u512 right = vm->stack()[stackSize - 2];
                        if (inst == Instruction::ADD)
                        {
                            auto add256 = left + right;
                            auto add512 = (u256)left + (u256)right;
                            // payload.isOverflow = total512 != total256;
                            // if (payload.isOverflow){
                            //     recordAdd=total512;
                            // }
                            if (add256 != add512)
                            {
                                payload.isOverflow = true;
                                isReallyFlow = true;
                                recordFlow = add512;
                            }
                        }
                        if (inst == Instruction::MUL)
                        {
                            auto mul256 = left * right;
                            auto mul512 = (u256)left * (u256)right;
                            if (mul256 != mul512)
                            {
                                payload.isOverflow = true;
                                isReallyFlow = true;
                                recordFlow = mul512;
                            }
                        }
                        if (inst == Instruction::SUB)
                            payload.isUnderflow = left < right;
                    }
                    payload.isReallyFlow = isReallyFlow;
                    oracleFactory->save(OpcodeContext(ext->depth, payload));
                }
                break;
            }
            }
            if (gasCost > gasLeft)
            {
                OpcodePayload payload;
                payload.pc = pc;
                payload.inst = inst;
                payload.isGasless = true;
                oracleFactory->save(OpcodeContext(ext->depth, payload));
            }
        }

        /* CompValue, distance to another branch, >=1 */
        switch (inst)
        {
        case Instruction::GT:
        case Instruction::SGT:
        case Instruction::LT:
        case Instruction::SLT:
        case Instruction::EQ: {
            vector<u256>::size_type stackSize = vm->stack().size();
            if (stackSize >= 2)
            {
                u256 left = vm->stack()[stackSize - 1];
                u256 right = vm->stack()[stackSize - 2];
                /* calculate if command inside a function */
                u256 temp = left > right ? left - right : right - left;
                lastCompValue = temp + 1;
                if (!is_prefuzz)
                {
                    // cout << left << " < " << right << endl;
                    OpcodePayload payload;
                    payload.pc = pc;
                    payload.inst = inst;
                    if (recordFlow != 0 && (left == recordFlow || right == recordFlow))
                        // cout << "fake overflow" << endl;
                        isReallyFlow = false;
                    payload.isReallyFlow = isReallyFlow;
                    if (left == 0 || right == 0)
                        payload.has0Condition = true;
                    oracleFactory->save(OpcodeContext(ext->depth, payload));
                }
            }
            break;
        }
        default: {
            break;
        }
        }

        /* Calculate left and right branches for valid jumpis*/
        // auto recordable0 = recordParam.isDeployment && get<0>(valids).count(pc);
        // recordable0 = recordable0 || !recordParam.isDeployment && get<1>(valids).count(pc);
        // auto recordable1 = recordParam.isDeployment && get<2>(valids).count(pc);
        // recordable1 = recordable1 || !recordParam.isDeployment && get<3>(valids).count(pc);
        auto recordable0 = recordParam.isDeployment && get<0>(valids).count(pc);
        auto recordable1 = !recordParam.isDeployment && get<1>(valids).count(pc);
        if (inst == Instruction::JUMPCI && (recordable0 || recordable1))
        {
            jumpDest1 = (u64)vm->stack().back();
            jumpDest2 = pc + 1;
            if (!is_prefuzz)  // record JUMPCI
            {
                OpcodePayload payload;
                payload.pc = pc;
                if (recordable0)
                    payload.inst = inst;
                else
                    payload.inst = inst;
                oracleFactory->save(OpcodeContext(ext->depth, payload));
            }
        }
        /* Calculate actual jumpdest and add reverse branch to predicate */
        // auto recordable = recordParam.isDeployment && (get<0>(valids).count(recordParam.lastpc) ||
        //                                                   get<2>(valids).count(recordParam.lastpc));
        // recordable = recordable ||
        //  !recordParam.isDeployment && (get<1>(valids).count(recordParam.lastpc) ||
                                                    //   get<3>(valids).count(recordParam.lastpc));
        auto recordable = recordParam.isDeployment && (get<0>(valids).count(recordParam.lastpc));
        recordable = recordable ||
                     !recordParam.isDeployment && (get<1>(valids).count(recordParam.lastpc));
        if (record_pc)
        {
            /* deploy case */
            // if (pc < 350)
            // cout << "PC: Gas : Cost    " << pc << " : " << gasLeft << " : " << gasCost << endl;
            // cout << hex << "0x" << pc << ": " << (int)inst << endl;
            // printf("%s,", to_string(pc).c_str());
            /* record pc list msg: */
            if (is_prefuzz && pc <= 8192)
            {
                auto iter = find(pclist.begin(), pclist.end(), (int)pc);
                // int loop_start = distance(pclist.begin(), iter);
                if (iter == pclist.end())
                {
                    // if (prevInst == Instruction::JUMPCI && pc == last_ppc + 1 && recordable)
                    // {
                    //     pclist.pop_back();
                    //     Logger::prefix(
                    //         "Present pc:" + to_string(pc) + " pre:" + to_string(last_ppc) +
                    //         "\n");
                    // }
                    /* avoid jump back, bran can not deal with it */
                    // Logger::prefix(to_string(pc) + ",");
                    if (pclist.empty() || pc > pclist.back())
                    {
                        pclist.push_back((int)pc);
                        // Logger::prefix(to_string(pc) + ",");
                        // cout << hex << "0x" << pc << ": " << (int)inst << endl;
                    }
                    // if (pc < last_ppc)
                    //     last_jump = pc_index;
                    // pc_index++;
                    // last_ppc = pc;
                }
                /* record loops msg */
                // else if (loop_start == last_branch + branch_len)
                // {
                //     if (loop.find(last_branch) == loop.end())
                //         loop.insert(pair<int, int>(last_branch, 1));
                //     else
                //         loop[last_branch]++;
                //     branch_len++;
                // }
                // else
                // {
                //     last_branch = loop_start;
                //     branch_len = 1;
                // }
            }

            if (prevInst == Instruction::JUMPCI && recordable)
            {
                auto branchId =
                    to_string(recordParam.lastpc) + ":" + to_string(pc);  // this branch id

                // just testing oracle here
                OpcodePayload payload;
                payload.pc = pc;
                payload.inst = inst;
                oracleFactory->save(OpcodeContext(ext->depth, payload));

                /*record prefix msg*/
                if (is_prefuzz && pc <= 8192)
                {
                    if (prefix_map.find(branchId) == prefix_map.end())
                    {
                        // prefix_map[branchId] = vector<int>(pclist.begin() + last_jump,
                        // pclist.end());
                        prefix_map[branchId] = pclist;
                        // prefix_map[branchId] = "";
                        // for (unsigned int i = 0; i < pclist.size(); i++)
                        // {
                        //     if (i == pclist.size() - 1)
                        //         prefix_map[branchId] += to_string(pclist[i]);
                        //     else
                        //         prefix_map[branchId] += to_string(pclist[i]) + ",";
                        // }
                        // loops[branchId] = loop;
                    }
                    // loop.clear();
                }

                /* ignore branch msgs in deployment */
                if (is_prefuzz)  // only record tracebit and the other branchId in prefuzz
                {
                    tracebits.insert(branchId);
                    /* Calculate branch distance */
                    u64 jumpDest = pc == jumpDest1 ? jumpDest2 : jumpDest1;
                    branchId = to_string(recordParam.lastpc) + ":" +
                               to_string(jumpDest);  // another branch id
                    if (lastCompValue == 0)
                        lastCompValue--;
                    predicates[branchId] = lastCompValue;
                }
                else
                {
                    if (reached_branch.find(branchId) != reached_branch.end())
                        reached_branch[branchId] += 1;
                    else
                        reached_branch[branchId] = 1;
                }
            }
        }
        prevInst = inst;
        recordParam.lastpc = pc;
    };

    program->deploy(addr, code);
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    oracleFactory->initialize();
    /* Record all JUMPI in constructor */
    recordParam.isDeployment = true;
    auto sender = ca.getSender();
    OpcodePayload payload;
    payload.pc = 0;
    payload.inst = Instruction::CALL;
    payload.data = ca.encodeConstructor();
    payload.wei = ca.isPayable("") ? program->getBalance(sender) / 2 : 0;
    payload.caller = sender;
    payload.callee = addr;
    oracleFactory->save(OpcodeContext(0, payload));
    auto res = program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""),
        onOp);  // no pc list record here
    transactionNum++;
    if (res.excepted != TransactionException::None)
    {
        auto exceptionId = to_string(recordParam.lastpc);
        uniqExceptions.insert(exceptionId);
        /* Save Call Log */
        payload.pc = recordParam.lastpc;
        OpcodePayload payload;
        payload.inst = Instruction::INVALID;
        oracleFactory->save(OpcodeContext(0, payload));
        // cout << "Exception Id :" << recordParam.lastpc << endl;
        // cout << "Exception Type :" << res.excepted << endl;
    }
    oracleFactory->finalize();
    record_pc = true;
    for (uint32_t funcIdx = 0; funcIdx < funcs.size(); funcIdx++)
    {
        /* Update payload */
        auto func = funcs[funcIdx];
        auto fd = ca.fds[funcIdx];
        // cout << fd.name << " : " << to_string(fd.tds.size()) << endl;
        /* Ignore JUMPI until program reaches inside function */
        recordParam.isDeployment = false;
        OpcodePayload payload;
        payload.data = func;
        payload.pc = 0;
        payload.inst = Instruction::CALL;
        payload.wei = ca.isPayable(fd.name) ? program->getBalance(sender) / 2 : 0;
        payload.caller = sender;
        payload.callee = addr;
        oracleFactory->save(OpcodeContext(0, payload));


        /*record prefix map (with inputs)*/
        // last_ppc = 0;
        res = program->invoke(
            addr, CONTRACT_FUNCTION, func, ca.isPayable(fd.name), onOp);  // pc list record
        transactionNum++;
        if (is_prefuzz)
        {
            Logger::prefix("\nBranch num :" + to_string(prefix_map.size()) + "\n");
            for (auto pmit : prefix_map)
            {
                // Logger::prefix(
                //     "pclist" + to_string(i) + " size: " + to_string(pclists[i].size()) + "\n");
                /* avoid record the same func prefix */
                if (func_map.find(pmit.first) == func_map.end())
                {
                    vector<FuncDef> fdlist;
                    fdlist.push_back(fd);
                    // func_map.insert(make_pair(pclist, fd));
                    func_map[pmit.first] = fdlist;
                    Logger::prefix("Prefix: \n");
                    for (auto it : pmit.second)
                        Logger::prefix(to_string(it) + " ");
                    Logger::prefix("\n");
                    // Logger::prefix(pmit.second + "\n");
                    // for (auto it : loops[pmit.first])
                    //     Logger::prefix("Loop start from " + to_string(it.first) + ", running " +
                    //                    to_string(it.second) + " times.\n");
                }
                // else
                // {
                //     if (find(func_map[pmit.first].begin(), func_map[pmit.first].end(), fd) ==
                //         func_map[pmit.first].end())
                //         func_map[pmit.first].push_back(fd);
                // }
            }
            pclist.clear();
            // last_jump = 0;
            // pc_index = 0;
        }

        outputs.push_back(res.output);
        if (res.excepted != TransactionException::None)
        {
            auto exceptionId = to_string(recordParam.lastpc);
            uniqExceptions.insert(exceptionId);
            // if (res.excepted != TransactionException::BadInstruction)
            // {
            //     cout << res.excepted << endl;
            // }
            /* Save Call Log */
            OpcodePayload payload;
            payload.pc = recordParam.lastpc;
            payload.inst = Instruction::INVALID;
            oracleFactory->save(OpcodeContext(0, payload));
        }
        oracleFactory->finalize();
    }
    // cout << "\n" << endl;

    /* Reset data before running new contract */
    program->rollback(savepoint);
    string cksum = "";
    for (auto t : tracebits)
        cksum = cksum + t;

    string current_testcase = "";
    if (!is_prefuzz)
        current_testcase = ca.toStandardJson();
    return TargetContainerResult(
        tracebits, predicates, prefix_map, reached_branch, uniqExceptions, cksum, current_testcase);
}
}  // namespace fuzzer
