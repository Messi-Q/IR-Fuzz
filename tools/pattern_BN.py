import os
import numpy as np
from libs import split_function
"""
Here is the method for extracting security patterns of blocknumber.
"""


# split all functions of contracts


def detectBN(filepath):
    allFunctionList = split_function(filepath)  # Store all functions
    BlockNumList = []
    contents = []
    for i in range(len(allFunctionList)):
        for j in range(len(allFunctionList[i])):
            text = allFunctionList[i][j]
            if 'block.number' in text:
                BlockNumList.append(allFunctionList[i])
                break
    for i in range(len(BlockNumList)):
        content = []
        BlockNumFlag1 = 0
        VarBlockNum = None
        for j in range(len(BlockNumList[i])):
            text = BlockNumList[i][j]
            if 'block.number' in text:
                BlockNumFlag1 = 1
                BlockNum = text.split("=")[0].strip().split()
                VarBlockNum = BlockNum[len(BlockNum) - 1]
                content.append(text)
            elif BlockNumFlag1 != 0:
                if VarBlockNum != " " or "" or "!":
                    if VarBlockNum in text:
                        content.append(text)
                if VarBlockNum in text and 'return' in text:
                    content.append(text)
        contents = list(set(content))
    return contents
