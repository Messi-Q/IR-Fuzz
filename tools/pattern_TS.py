import os
import numpy as np
from libs import split_function

"""
Here is the method for extracting security patterns of timestamp dependence.
"""
def detectDS(filepath):
    allFunctionList = split_function(filepath)  # Store all functions
    timeStampList = []
    contents = []
    for i in range(len(allFunctionList)):
        for j in range(len(allFunctionList[i])):
            text = allFunctionList[i][j]
            if 'block.timestamp' in text:
                timeStampList.append(allFunctionList[i])
                break
    for i in range(len(timeStampList)):
        content = []
        TimestampFlag1 = 0
        VarTimestamp = None
        for j in range(len(timeStampList[i])):
            text = timeStampList[i][j]
            if 'block.timestamp' in text:
                TimestampFlag1 = 1
                Timestamp = text.split("=")[0].strip().split()
                VarTimestamp = Timestamp[len(Timestamp) - 1]
                content.append(text)
            elif TimestampFlag1 != 0:
                if VarTimestamp != " " or "" or "!":
                    if VarTimestamp in text:
                        content.append(text)
                if VarTimestamp in text and 'return' in text:
                    content.append(text)
        contents = list(set(content))
    return contents
