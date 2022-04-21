# !/bin/bash
mkdir source_codes contracts logs branch_msg sFuzz/build

cd sFuzz/build/
cmake ..
cd fuzzer/
make

cd ../../../bran/
go build -v -o ../analyse_prefix