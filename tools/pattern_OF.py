import os
import numpy as np

def detectOF(filepath):
    target=[]
    try:
        f=open(filepath,'r')
    except:
        print("empty contract file!")
    lines=f.readlines()
    flag = True
    for line in lines:
        if len(line.strip())>0 and line!='\n':
            if line.strip().startswith("/*"):
                flag = False
                continue
            elif line.strip().startswith("*/"):
                flag = True
                continue
            elif not line.strip().startswith("//") and flag:
                end=line.find("//")
                if '+' in line or '-' in line or '/' in line or '*' in line:
                    if line.find('+')>end or line.find('-')>end or line.find('/')>end or line.find('*')>end:
                        target.append(line.strip())
    return target
def main():
    inputFileDir = "../contracts/"
    dirs = []
    targets = {}
    try:
        dirs = os.listdir(inputFileDir)
    except:
        print("contracts path error!")
    for file in dirs:
        target = []
        if len(file.split(".")) <= 2 and file.split(".")[1] == "sol":
            target, flag = detectOF(inputFileDir, file)
            if not flag:
                continue
            contractName = file.split(".")[0]
            targets[contractName] = list(set(target))
    #print(targets)

if __name__=="__main__":
    main()
