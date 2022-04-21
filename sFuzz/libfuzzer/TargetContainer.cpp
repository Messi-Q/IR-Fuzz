#include "TargetContainer.h"
#include "ContractABI.h"
#include "Util.h"
#include <math.h>
#include <boost/multiprecision/cpp_dec_float.hpp>

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;
using namespace boost::multiprecision;

namespace fuzzer
{
TargetContainer::TargetContainer()
{
    program = new TargetProgram();
    oracleFactory = new OracleFactory();
    baseAddress = ATTACKER_ADDRESS;
}

TargetExecutive TargetContainer::loadContract(bytes code, ContractABI ca)
{
    if (baseAddress > CONTRACT_ADDRESS)
    {
        cout << "> Currently does not allow to load more than 1 asset contract" << endl;
        exit(0);
    }
    Address addr(baseAddress);
    TargetExecutive te(oracleFactory, program, addr, ca, code);
    baseAddress++;
    return te;
}

TargetExecutive TargetContainer::loadContract(bytes code, ContractABI ca, Address addr)
{
    if (addr < CONTRACT_ADDRESS)
    {
        cout << "> Currently does not allow to load non-library contracts" << endl;
        exit(0);
    }
    TargetExecutive te(oracleFactory, program, addr, ca, code);
    return te;
}

TargetProgram* TargetContainer::getProgram()
{
    return program;
}

TargetContainer::~TargetContainer()
{
    delete program;
    delete oracleFactory;
}
}  // namespace fuzzer
