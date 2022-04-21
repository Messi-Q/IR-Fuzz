# IR-Fuzz

An Effective Fuzzing framework for Smart Contract Vulnerability Detection.


## Requirements

IR-Fuzz is supported on Linux (ideally Ubuntu 18.04).

Dependencies: 

* [CMake](https://cmake.org/download/): >=[3.5.1](sFuzz/CMakeLists.txt#L5)
* [Python](https://www.python.org/downloads/): >=3.5（ideally 3.6）
* Go: 1.15
* leveldb

## Architecture

```shell
$(IR-Fuzz)
├── sFuzz
│   ├── fuzzer
│   ├── libfuzzer
│   ├── liboracle
│   └── ...
├── bran
│   └── ...
├── tools
│   ├── requirements.txt
│   └── ...
├── assets
│   ├── ReentrancyAttacker_model.sol
│   ├── ReentrancyAttacker.sol
│   └── ...
├── source_code
│   └── ...
├── contracts
│   └── ...
├── branch_msg
│   └── ...
├── logs
│   └── ...
├── fuzz
├── initial_.sh
├── rename_src.sh
├── run.sh
└── README.md
```

* `sFuzz`: The fuzzing module of IR-Fuzz
* `bran`: The abstract interpreter for path analysis
* `tools`: The static analysis tools for extracting vulnerability-specific patterns
  * `requirements.txt`：Required python dependencies
* `assets`:
  * `ReentrancyAttacker_model.sol`: The template for constructing an attacker contract
  * `ReentrancyAttacker.sol`: The attacker contract generated based on the template
* `source_code`: Store the source code of the contract under test
* `contracts/example1`: Store the compiled results of the contract under test
* `branch_msg`: Store the intermediate representations of the contract under test
* `logs`: Store the execution report during fuzzing
* `fuzz`: Execute the fuzzer

## Quick Start

- Initialization and Install system dependencies

```bash
./initial_.sh
```

- Make workspace for the contract in directory `source_code`

```bash
./rename_src.sh
```

- Run IR-Fuzz and perform vulnerability detection

```bash
./run.sh
```

- Note: the code is adapted from [sFuzz](https://github.com/duytai/sFuzz) (a state-of-the-art fuzzer for smart contracts) and [bran](https://github.com/Practical-Formal-Methods/bran) (a static analysis framework for EVM bytecode). 

## Dataset
We release the benchmark dataset collected from Etherescan, which contains over 12K Ethereum smart contracts and concerns eight types of vulnerabilities. Download the benchmark dataset at [Smart contract dataset](https://drive.google.com/file/d/1AgPCDGBW3Z52bTBMn_FyEqBNypjy0XFh/view?usp=sharing).
