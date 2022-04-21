import json
import os

from pattern_TS import detectDS

from pattern_BN import detectBN
from pattern_DC import detectDC
from pattern_OF import detectOF
from pattern_RE import detectRE
from pattern_UE import detectUE
from libs import splitOpcode
from libs import decompressSourcemap
from libs import load

from libs import readContracts


def readtxt(file):
    with open(file, 'r')as f:
        data = f.read()
        return data


def findTarget(contents, contract, opcodeList, List, length):
    opcode_output = []
    #print(length)
    for i in range(len(List)):
        if i >= length:
            break
        offset = List[i][0]
        l = List[i][1]
        if opcodeList[i][1].strip() == 'JUMPI':
            offset = List[i][0]
            l = List[i][1]
            snippet = contract[offset:offset + l]
            #print(snippet)
            #print(contents)
            if not snippet.strip().startswith("contract"):
                    for j in contents:
                        for k in j:
                            if str(k).rstrip(';') in snippet or snippet in str(k):
                                opcode_output.append(int(opcodeList[i][0], 16))
    return opcode_output


def findPosition(inputFileDir, file):
    inputFilePath = inputFileDir + file
    FileName = file.split('.')[0]
    inputFileName = inputFileDir.split("../")[1] + file
    inputAsmPath = inputFileDir+FileName+'.asm'
    opcode_outputs = {}
    name = file.split(".")[0]
    opcode_output2 = []
    List2 = []
    l2 = []
    opcode_output = []
    targets = {}
    contents=[]
    try :
        data = load(inputFilePath+'.json')
        srcmap_runtime = data["contracts"][inputFileName + ":" + name]["srcmap-runtime"]
    except:
        print("empty json file!")
        return "",False
    contract = readContracts(inputFilePath)
    try :
        opcodes_runtime = readtxt(inputAsmPath)
    except:
        print("empty asm file!")
        return "", False
    contents.append(detectDS(inputFilePath))
    contents.append(detectBN(inputFilePath))
    contents.append(detectOF(inputFilePath))
    contents.append(detectRE(inputFilePath))
    contents.append(detectDC(inputFilePath))
    contents.append(detectUE(inputFilePath))
    srcList_runtime = srcmap_runtime
    try:
        List2 = decompressSourcemap(srcList_runtime)
        opcodeList = splitOpcode(opcodes_runtime)
        l2 = len(List2)
    except:
        print("empty runtime file!")
        return "",False

    try:
      opcode_output2 = findTarget(contents, contract, opcodeList, List2, len(opcodeList))
    except:
        print("empty asm file!")
        return "", False
    for i in opcode_output2:
        opcode_output.append(i)
    # opcode_output.append(opcode_output2)
    # for i in range(len(List1)):
    #     if i>len(opcodes)-len(opcodes_runtime):
    #         break
    #     if opcodeList[i][1].strip() =='JUMPI':
    #         offset = List1[i][0]
    #         l = List1[i][1]
    #         snippet = contract[offset:offset + l]
    #         if not snippet.strip().startswith("contract"):
    #             for k in contents[0]:
    #                 if str(k) in snippet:
    #                     opcode_output.append(int(opcodeList[i][0], 16))
    #                     print(snippet)
    # for i in range(len(List2)):
    #     if opcodeList2[i][1].strip() == 'JUMPI':
    #         offset = List2[i][0]
    #         l = List2[i][1]
    #         snippet = contract[offset:offset + l]
    #         if not snippet.strip().startswith("contract"):
    #             for k in contents[0]:
    #                 if str(k) in snippet:
    #                     opcode_output.append(int(opcodeList2[i][0], 16))
    #                     print(snippet)
    opcode_outputs[name] = list(set(opcode_output))
    # print(opcode_outputs)
    return opcode_outputs,True


def TSDetection():
    inputFileDir = "../contracts/"
    outputFileDir = "../branch_msg/targets.json"
    outputs = {}
    Files = os.listdir(inputFileDir)
    for dir in Files:
        dir = inputFileDir + dir + '/'
        files = os.listdir(dir)
        for file in files:
            if len(file.split(".")) <= 2 and file.split(".")[1] == "sol":
                output,flag = findPosition(dir, file)
                if not flag:
                    continue
                outputs.update(output)
    with open(outputFileDir, 'w') as f:
        json.dump(outputs, f)

if __name__ == '__main__':
    TSDetection()