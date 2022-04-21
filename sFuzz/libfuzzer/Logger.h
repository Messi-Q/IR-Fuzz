#pragma once
#include "Common.h"
#include <fstream>
#include <iostream>

using namespace dev;
using namespace eth;
using namespace std;
namespace fuzzer
{
class Logger
{
public:
    static bool enabled;
    static ofstream debugFile;
    static ofstream infoFile;
    static ofstream prefixFile;
    static void setEnabled(bool _enabled);
    static void info(string str);
    static void debug(string str);
    static void prefix(string str);
    static string testFormat(bytes data);
};
}  // namespace fuzzer
