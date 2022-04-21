import os
import numpy as np
from libs import split_function

"""
Here is the method for extracting security patterns of unexpected ether balance.
"""


def detectUE(filepath):
    allFunctionList = split_function(filepath)
    unexpectedEthList = []
    contents = []
    for i in range(len(allFunctionList)):
        for j in range(len(allFunctionList[i])):
            text = allFunctionList[i][j]
            if 'balance' in text:
                unexpectedEthList.append(allFunctionList[i])
                break
    for i in range(len(unexpectedEthList)):
        content = []
        UEFlag1 = 0
        VarUnexpectedEth = None
        for j in range(len(unexpectedEthList[i])):
            text = unexpectedEthList[i][j]
            if 'balance' in text:
                UEFlag1 = 1
                UnexpectedEth = text.split("=")[0].strip().split()
                VarUnexpectedEth = UnexpectedEth[len(UnexpectedEth) - 1]
                index = text.find('balance')
                line = text[index:len(text)]
                content.append(line)
            elif UEFlag1 != 0:
                if VarUnexpectedEth != " " or "" or "!":
                    if VarUnexpectedEth in text:
                        index = text.find(VarUnexpectedEth)
                        line = text[index:len(text)]
                        content.append(line)
                if VarUnexpectedEth in text and 'return' in text:
                    index = text.find(VarUnexpectedEth)
                    line = text[index:len(text)]
                    content.append(line)
        contents = list(set(content))
    return contents