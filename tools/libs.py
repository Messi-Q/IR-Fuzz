import json
import os


# split all functions of contracts
def split_function(filepath):
    function_list = []
    f = open(filepath, 'r')
    lines = f.readlines()
    f.close()
    flag = -1
    for line in lines:
        text = line.strip()
        if len(text) > 0 and text != "\n":
            if text.split()[0] == "function" or text.split()[0] == "function()":
                function_list.append([text])
                flag += 1
            elif len(function_list) > 0 and ("function" in function_list[flag][0]):
                function_list[flag].append(text)
    return function_list


def splitOpcode(opcode):
    opcodeList = []
    opcodes = opcode.split('\n')
    for i in opcodes:
        if i != '' and i != ' ':
            h = i.split(":")[0]
            l = i.split(":")[1]
            opcodeList.append((h, l))
    return opcodeList


def readContracts(file):
    with open(file, 'r') as f:
        data = f.read()
        return data


def load(file):
    with open(file, 'r') as f:
        data = json.loads(f.read())
        return data


def decompressSourcemap(srcmap):
    list = []
    srcmapList = srcmap.split(';')
    for i in srcmapList:
        k = 0
        j = i.split(":")
        if len(j) >= 1 and j[0] != '':
            s = int(j[0])
        else:
            s = list[k - 1][0]
        if len(j) >= 2 and j[1] != '':
            l = int(j[1])
        else:
            l = list[k - 1][1]
        k += 1
        list.append((s, l))
    return list
