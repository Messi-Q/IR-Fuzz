# !/bin/bash
cd tools/
python3 pre_analysis.py
cd ..
./fuzz -g -p -r 2 -d 5 && chmod +x fuzzMe && ./fuzzMe

d1=`ls ./contracts/`
for i in $d1
do 
	if [ -d "./contracts/$i" ];then
		d2=`ls ./contracts/$i`
		for j in $d2
		do
			if [ "${j##*.}"x = "sol"x ];then
				eval "solc --bin-runtime --overwrite ./contracts/${i}/${j} -o ./contracts/${i}/"
				name=$(basename $j .sol)
				if [ ! -f $name".bin-runtime" ];then
					echo $name
					eval "evm disasm ./contracts/${i}/$name.bin-runtime |tail -n +2 > ./contracts/${i}/$name.asm"
				fi
			fi
		done
	fi
done 

cd tools/
python3 get_targetLoc.py
cd ..
./analyse_prefix > logs/analyze.txt

./fuzz -g -r 2 -d 1000 -t 5 && chmod +x fuzzMe && ./fuzzMe

cd tools/
python3 get_VulnerabilityLoc.py
