#include "Logger.h"

using namespace std;

namespace fuzzer
{
ofstream Logger::debugFile = ofstream("logs/debug.txt", ios_base::app);
ofstream Logger::infoFile = ofstream("logs/info.txt", ios_base::app);
ofstream Logger::prefixFile = ofstream("logs/prefix.txt", ios_base::app);

bool Logger::enabled = true;

void Logger::debug(string str)
{
    if (enabled)
    {
        debugFile << str << endl;
    }
}

void Logger::info(string str)
{
    if (enabled)
    {
        infoFile << hex << str << endl;
    }
}

void Logger::prefix(string str)
{
    if (enabled)
    {
        prefixFile << str;
    }
}

string Logger::testFormat(bytes data)
{
    auto idx = 0;
    stringstream ss;
    while (idx < data.size())
    {
        bytes d(data.begin() + idx, data.begin() + idx + 32);
        idx += 32;
        ss << toHex(d) << endl;
    }
    return ss.str();
}
}  // namespace fuzzer
