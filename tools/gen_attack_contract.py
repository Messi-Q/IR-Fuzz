import os
import sys
import json


def para_input():
    name = ""
    if len(sys.argv) > 2:
        sys.exit("parameter error!")
    if len(sys.argv) == 2:
        name = sys.argv[1]
    return name


def read_model():
    file = "./assets/ReentrancyAttacker_model.sol"
    with open(file, "r") as f:
        lines = f.readlines()
    return lines


def find_json_path(obj, currerent_path, target):
    if isinstance(obj, dict):
        key_value_iterator = (x for x in obj.items())
    elif isinstance(obj, list):
        key_value_iterator = (x for x in enumerate(obj))
    else:
        return

    for key, value in key_value_iterator:
        path = currerent_path.copy()
        path.append(key)
        if key == target:
            yield path
        if isinstance(value, (dict, list)):
            yield from find_json_path(value, path, target)


def gen_attacker_call(name):
    contract = name.split("/")[-1]
    contract = contract.split(".sol")[0]
    file = "./" + name + ".json"
    calls = []
    inputs = []
    with open(file, "r") as f:
        try:
            jsons = json.load(f)
        except:
            exit(1)
        abis = json.loads(jsons["contracts"][name + ":" + contract]["abi"])
        ast_nodes = jsons["sources"][name]["AST"]["children"]
        name_list = []
        # print(json.dumps(abis, sort_keys=True, indent=4, separators=(',', ':')))
        # print(ast_nodes)

        for anode in ast_nodes:
            try:
                attribute = anode["attributes"]
                if "name" in attribute.keys() and attribute["name"] == contract:
                    ast_nodes = anode["children"]
                    break
            except:
                pass
        for anode in ast_nodes:
            try:
                attribute = anode["attributes"]
                if "name" in attribute.keys():
                    name_list.append(attribute["name"])
            except:
                pass
        # print(name_list)

        path_iter = list(find_json_path(abis, [], "type"))
        for path in path_iter:
            node = abis.copy()
            for step in path:
                if step == path[-1]:
                    break
                node = node[step]
            if node["type"] == "function" and node["constant"] == False:
                # print(node)
                # print(name_list)
                if node["name"] not in name_list:
                    continue
                ast_func = ast_nodes[name_list.index(node["name"])]
                if len(ast_func) != 0:
                    may_call = list(find_json_path(ast_func["children"], [], "name"))
                    i = 0
                    for fname in may_call:
                        may_call_name = ast_func["children"].copy()
                        for n in fname:
                            may_call_name = may_call_name[n]
                        i += 1
                        # print(may_call_name)
                        if may_call_name == "FunctionCall":
                            break
                    if i == len(fname):
                        continue

                call_func = node["name"] + "("
                type_list = []
                input_list = []
                for i in node["inputs"]:
                    type_list.append(i["type"])
                    if "bool" in i["type"]:
                        input_list.append("1")
                    elif "int" in i["type"]:
                        input_list.append("1")
                    elif "fixed" in i["type"]:
                        input_list.append("0.1")
                    elif "address" in i["type"]:
                        input_list.append("0xf1")
                    elif "byte" in i["type"]:
                        input_list.append("0xf1")
                    elif "string" in i["type"]:
                        input_list.append("\"aaa\"")

                call_func += ",".join(type_list) + ")"
                calls.append(call_func)
                inputs.append(input_list)
        # print(calls)
        # print(inputs)
        return calls, inputs


def gen_call_statement(contents, calls, inputs):
    index = 0
    for i, value in enumerate(contents):
        if "msg.sender.call" in value:
            index = i
            break
    # print(content[index])
    str_head = "            require(msg.sender.call(abi.encode(keccak256(\""
    if len(calls) == 1:
        if len(inputs[0]) > 0:
            contents[index] = str_head + calls[0] + "\")), " + ", ".join(inputs[0]) + "));\n"
        else:
            contents[index] = str_head + calls[0] + "\"))));\n"
    elif len(calls) > 1:
        del contents[index]
        for i in range(len(calls)):
            if len(inputs[i]) > 0:
                contents.insert(index, str_head + calls[i] + "\")), " + ", ".join(inputs[i]) + "));\n")
            else:
                contents.insert(index, str_head + calls[i] + "\"))));\n")
            # print(contents[index + i])
    return contents


def write_attacker(contents):
    file = "./assets/ReentrancyAttacker.sol"
    with open(file, "wt") as f:
        f.writelines(contents)



if __name__ == '__main__':
    attacker_name = para_input()
    content = read_model()
    if len(attacker_name) != 0:
        call_list, inputs_list = gen_attacker_call(attacker_name)
    write_attacker(gen_call_statement(content, call_list, inputs_list))

