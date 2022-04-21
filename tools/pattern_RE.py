import os
import numpy as np
from libs import split_function

def detectRE(filepath):
    allFunctionList = split_function(filepath)  # Store all functions
    callValueList = []
    contents = []
    content = []
    for i in range(len(allFunctionList)):
        for j in range(len(allFunctionList[i])):
            text = allFunctionList[i][j]
            if 'onlyOwner' in text or 'require(owner' in text:
                break
            elif 'call.value' in text:
                content.append(text)
    contents = list(set(content))
    return contents
