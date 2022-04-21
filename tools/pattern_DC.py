import os
import numpy as np
from libs import split_function

"""
Here is the method for extracting security patterns of delegatecall.
"""


def detectDC(filepath):
    allFunctionList = split_function(filepath)
    delegateCallList = []
    contents = []
    content=[]
    for i in range(len(allFunctionList)):
        for j in range(len(allFunctionList[i])):
            text = allFunctionList[i][j]
            if 'delegatecall' in text:
                index=text.find('delegatecall')
                line = text[index:len(text)]
                content.append(line)
    contents = list(set(content))
    return contents