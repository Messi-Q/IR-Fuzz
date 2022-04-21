#include "Utils.h"
#include <libfuzzer/Fuzzer.h>
#include <iostream>

using namespace std;
using namespace fuzzer;

static int DEFAULT_MODE = AFL;
static int DEFAULT_DURATION = 5;  // 5 sec
static int DEFAULT_REPORTER = JSON;
static int DEFAULT_ANALYZING_INTERVAL = 5;  // 5 sec
static int DEFAULT_TESTCASES_NUM = 1;
static string DEFAULT_CONTRACTS_FOLDER = "contracts/";
static string DEFAULT_ASSETS_FOLDER = "assets/";
static string DEFAULT_ATTACKER = "ReentrancyAttacker";

int main(int argc, char* argv[])
{
    /* Run EVM silently */
    dev::LoggingOptions logOptions;
    logOptions.verbosity = VerbositySilent;
    dev::setupLogging(logOptions);
    /* Program options */
    int mode = DEFAULT_MODE;
    int duration = DEFAULT_DURATION;
    int case_num = DEFAULT_TESTCASES_NUM;
    int reporter = DEFAULT_REPORTER;
    string contractsFolder = DEFAULT_CONTRACTS_FOLDER;
    string assetsFolder = DEFAULT_ASSETS_FOLDER;
    string jsonFile = "";
    string contractName = "";
    string sourceFile = "";
    string attackerName = DEFAULT_ATTACKER;
    po::options_description desc("Allowed options");
    po::variables_map vm;

    desc.add_options()("help,h", "produce help message")("contracts,c", po::value(&contractsFolder),
        "contract's folder path")("generate,g", "g fuzzMe script")("assets,a",
        po::value(&assetsFolder),
        "asset's folder path")("file,f", po::value(&jsonFile), "fuzz a contract")(
        "name,n", po::value(&contractName), "contract name")("source,s", po::value(&sourceFile),
        "source file path")("mode,m", po::value(&mode), "choose mode: 0 - AFL ")(
        "reporter,r", po::value(&reporter), "choose reporter: 0 - TERMINAL | 1 - JSON | 2 - BOTH")(
        "duration,d", po::value(&duration), "fuzz duration")("attacker", po::value(&attackerName),
        "choose attacker: NormalAttacker | ReentrancyAttacker")(
        "prefuzz,p", "get prefix of each branch")(
        "testcases,t", po::value(&case_num), "expected test cases number");
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);
    /* Show help message */
    if (vm.count("help"))
        showHelp(desc);
    /* Generate working scripts */
    if (vm.count("generate"))
    {
        std::ofstream fuzzMe("fuzzMe");
        fuzzMe << "#!/bin/bash" << endl;
        if (vm.count("prefuzz"))
        {
            fuzzMe << compileSolFiles(contractsFolder);
            fuzzMe << compileSolFiles(assetsFolder, attackerName);
        }
        fuzzMe << fuzzJsonFiles(contractsFolder, assetsFolder, duration, case_num, mode, reporter,
            attackerName, vm.count("prefuzz"));
        fuzzMe.close();
        showGenerate();
        return 0;
    }
    /* Fuzz a single contract */
    if (vm.count("file") && vm.count("name") && vm.count("source"))
    {
        FuzzParam fuzzParam;
        auto contractInfo = parseAssets(assetsFolder);
        contractInfo.push_back(parseSource(sourceFile, jsonFile, contractName, true));
        fuzzParam.contractInfo = contractInfo;
        fuzzParam.mode = (FuzzMode)mode;
        fuzzParam.duration = duration;
        fuzzParam.case_num = abs(case_num);
        fuzzParam.reporter = (Reporter)reporter;
        fuzzParam.analyzingInterval = DEFAULT_ANALYZING_INTERVAL;
        fuzzParam.attackerName = attackerName;
        fuzzParam.is_prefuzz = vm.count("prefuzz");
        Fuzzer fuzzer(fuzzParam);
        cout << ">> Fuzz " << contractName << endl;
        fuzzer.start();
        return 0;
    }
    return 0;
}
