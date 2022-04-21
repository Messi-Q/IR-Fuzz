import os


def split_contract(file):
    contract_list = {}
    contract = ''
    lines = file.readlines()
    new_contractname = ''
    flag = False
    for line in lines:
        if line.strip().startswith("contract"):
            if new_contractname != '':
                contract_list[new_contractname] = contract
            new_contractname = line.split(" ", 2)[1].strip()
            contract = line
        elif line.strip().startswith("library") or line.strip().startswith("interface"):
            flag = True
        elif line.strip().endswith('}'):
            flag=False
        elif not flag:
            contract += line
    contract_list[new_contractname] = contract
    return contract_list


def split_function(f):
    function_list = []
    pc = []
    lines = f.readlines()
    flag = -1
    index = 0
    for line in lines:
        index += 1
        text = line.strip()
        if len(text) > 0:
            if text.split()[0] == "function" or text.split()[0] == "function()":
                function_list.append([line])
                flag += 1
                pc.append(index)
            elif len(function_list) > 0 and ("function" in function_list[flag][0]):
                function_list[flag].append(line)
    return function_list, pc


def testAnalysis(inputDir, file):
    filepath = inputDir + file
    functionList = []
    output = []
    index = 0
    contractList = []
    try:
        f = open(filepath, 'r')
        contractList = split_contract(f)
    except:
        print("empty contract file!")
        return "", False
    try:
        f = open(filepath, 'r')
        functionList, pc = split_function(f)
    except:
        print("empty contract file!")
        return "", "", False
    contractNames = []
    for func in functionList:
        fstr = ''
        for line in func:
            fstr += line
        index1 = fstr.find('{')
        index2 = fstr.find(';')
        if index2 != -1 and (index1 >= index2 or index1 < 0):
            for contractName in contractList:
                if fstr.split(';')[0]+';' in contractList[contractName]:
                    contractNames.append(contractName)
            output.append(str(pc[index]))
        index += 1
    return output, set(contractNames), True


def main():
    inputFileDir = "../contracts/"
    outputs = {}
    Files = os.listdir(inputFileDir)
    for dir in Files:
        dir = inputFileDir + dir + '/'
        files = os.listdir(dir)
        for file in files:
            outputFileDir = dir + file.split(".")[0] + '_report.json'
            if len(file.split(".")) <= 2 and file.split(".")[1] == "sol":
                output, contractNames, flag = testAnalysis(dir, file)
                if not flag:
                    continue
                contractName = file.split(".")[0]
                # print(contractName)
                outputs[contractName] = list(set(output))
                for c in contractNames:
                    if c == contractName.split('.')[0]:
                        print(c + ".sol may be absract, not implement an abstract parent's methods completely  \n"
                                  "or not invoke an inherited contract's constructor correctly. ERROR: at line " + ','.join(
                            output))
                        try:
                            os.rename(dir + c + ".sol", dir + c + ".sol.err")
                        except:
                            print("file is not found!!!")
    # print(outputs)
    if ~len(outputs):
        print("Pre analyze success!\nPrefuzzing start :")


if __name__ == '__main__':
    main()
