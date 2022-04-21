import os
import sys
import json
from operator import itemgetter

from gen_attack_contract import para_input

fdList = []
param_list = dict()  # param of current contract
modifier_dataDependency = dict()
funcs_dataDependency = dict()  # param data dependency of each functions
funcs_order = dict()


def init_fdList(abis):
    for node in abis:
        param_len = "0"
        try:
            param_len = str(len(node["inputs"]))
        except:
            pass
        if node["type"] == "fallback":
            funcs_order["fallback," + node["stateMutability"] + ":" + param_len] = 0
        if node["type"] == "function" and not node["constant"]:
            fdList.append(node["name"])
            funcs_order[node["name"] + ":" + param_len] = 0


def init_paramList(_ast_nodes):
    for _anode in _ast_nodes:
        _name = _anode["name"]
        if "attributes" not in _anode.keys():
            continue
        _attribute = _anode["attributes"]
        if _name == "VariableDeclaration":
            if "[]" in _attribute["type"]:  # If the parameter is array
                param_list[_attribute["name"]] = 1
            elif "mapping" in _attribute["type"]:
                param_list[_attribute["name"]] = 2
            else:
                param_list[_attribute["name"]] = 0


def find_param_path(obj, _currerent_path):
    if isinstance(obj, dict):
        key_value_iterator = (x for x in obj.items())
    elif isinstance(obj, list):
        key_value_iterator = (x for x in enumerate(obj))
    else:
        return

    _params = list(param_list.keys())
    _params.append("PlaceholderStatement")

    for key, value in key_value_iterator:
        path = _currerent_path.copy()
        path.append(key)
        if value in _params or value in fdList:
            yield path
        if isinstance(value, (dict, list)):
            yield from find_param_path(value, path)


def get_dataDependency(_ast_nodes, _interfaceType, _recordParm):
    for _anode in _ast_nodes:
        if "attributes" not in _anode.keys() or\
                "isConstructor" not in _anode["attributes"].keys():
            continue
        _name = _anode["name"]
        if _name == _interfaceType:
            _fName = _anode["attributes"]["name"]
            if _anode["attributes"]["isConstructor"]:
                _fName = "constructor"
            if _fName == "":
                _fName = "fallback" + "," + _anode["attributes"]["stateMutability"]
            _fName += ":" + str(len(_anode["children"][0]["children"]))
            if _fName not in _recordParm.keys():
                _recordParm[_fName] = []
            for _funNode in _anode["children"]:
                _name = _funNode["name"]
                if _name == "Block":
                    path_iter = list(find_param_path(_funNode["children"], []))
                    for path in path_iter:
                        node = _funNode["children"].copy()
                        _opt = []
                        _optStep = []
                        for step in path:
                            if step == path[-1]:
                                break
                            if len(path) > 2 and step == path[-3]:  # rules of abi.json, find param option
                                try:
                                    # print(json.dumps(node[path[-3]]["name"], indent=4))
                                    _opt.append(node[path[-3]]["name"])
                                    _optStep.append(node[path[-3]]["children"][0]["name"])
                                    # _optStep.append(step)
                                except:
                                    pass
                                # _optT = node[path[-3]]["name"]
                            node = node[step]
                        # print(json.dumps(_opt, indent=4))
                        # print(json.dumps(node, indent=4))
                        # print(path)
                        # print(_opt)
                        # print(json.dumps(_optStep, indent=4))
                        # print(_optStep)
                        # print(_opt)
                        # print("\n")
                        # print(_opt[-2])
                        _rwIsRecord = False
                        _fnode = ""
                        if "function" in node["type"]:
                            _fnode = node[step] + ":" + str(
                                len(node["argumentTypes"]) if node["argumentTypes"] else 0
                                )
                        node = node[step]
                        if _fnode in list(funcs_dataDependency.keys()):
                            _rw = {_fnode: "FunctionCall"}
                        elif _fnode != "":
                            continue
                        elif node == "PlaceholderStatement":
                            _rw = {node: "_"}
                        elif len(_opt) > 1:
                            _keyOpt = ""
                            if param_list[node] != 2:
                                _keyOpt = _opt[-2]
                            elif len(_opt) > 2:
                                _keyOpt = _opt[-3]
                            # print(node)
                            # print(_opt)
                            # print("\n")
                            if _optStep[0] == "FunctionCall":
                                _rw = {node: "r"}
                                _recordParm[_fName].insert(-1, _rw)
                                _rwIsRecord = True
                            elif _keyOpt == "Assignment" or \
                                    (param_list[node] == 1 and _keyOpt == "MemberAccess"):
                                _rw = {node: "w"}
                            else:
                                _rw = {node: "r"}
                        # elif (param_list[node] == 0 and len(_opt) > 1 and _opt[-2] == "Assignment") or \
                        #         (param_list[node] == 1 and len(_opt) > 1 and _opt[-2] == "MemberAccess") or \
                        #         (param_list[node] == 2 and len(_opt) > 2 and _opt[-3] == "Assignment"):
                        #     _rw = {node: "w"}
                        else:
                            _rw = {node: "r"}

                        if not _rwIsRecord:
                            _recordParm[_fName].append(_rw)


def m_dataDependency(_ast_nodes, _beforePlaceholder):
    for _anode in _ast_nodes:
        _name = _anode["name"]
        if _name == "FunctionDefinition":
            _fName = _anode["attributes"]["name"]
            if _anode["attributes"]["isConstructor"]:
                _fName = "constructor"
            if _fName == "":
                _fName = "fallback" + "," + _anode["attributes"]["stateMutability"]
            _fName += ":" + str(len(_anode["children"][0]["children"]))
            if _fName not in funcs_dataDependency.keys():
                funcs_dataDependency[_fName] = []
            for _funNode in _anode["children"]:
                _name = _funNode["name"]
                if _name == "ModifierInvocation":
                    for _m in _funNode["children"]:
                        if _m["name"] != "Identifier":
                            continue
                        if _m["attributes"]["value"] not in modifier_dataDependency.keys():
                            continue
                        _reachPlaceholder = False
                        # print(_m["attributes"]["value"])
                        for _rws in modifier_dataDependency[_m["attributes"]["value"]]:
                            key = list(_rws.keys())[0]
                            value = list(_rws.values())[0]
                            if value == "_":
                                _reachPlaceholder = True
                                continue
                            if _beforePlaceholder:
                                if _reachPlaceholder:
                                    break
                                funcs_dataDependency[_fName].append({key: value})
                            else:
                                if not _reachPlaceholder or value == "_":
                                    continue
                                funcs_dataDependency[_fName].append({key: value})


def replace_internalCall():
    for _name, _params in funcs_dataDependency.items():
        _index = 0
        for _rw in _params:
            _key = list(_rw.keys())[0]
            _value = list(_rw.values())[0]
            if _value == "FunctionCall":
                del funcs_dataDependency[_name][_index]
                if _key in funcs_dataDependency.keys():
                    _calledParams = list(reversed(funcs_dataDependency[_key]))
                    for _itm in _calledParams:
                        funcs_dataDependency[_name].insert(_index, _itm)
            _index += 1


def get_funcsOrder():
    if funcs_dataDependency:
        funcs_weight = dict()

        for func in funcs_dataDependency.keys():
            funcs_weight[func] = 0

        for func, params in funcs_dataDependency.items():
            weightList = []
            for p in params:
                if list(p.values())[0] == "r":
                    dependedPara = list(p.keys())[0]
                    for func_x, params_x in funcs_dataDependency.items():
                        if func_x == func or func_x in weightList:
                            continue
                        for px in params_x:
                            if list(px.keys())[0] == dependedPara and list(px.values())[0] == "w":
                                weightList.append(func_x)
            weightList.reverse()
            w = 1
            for fw in weightList:
                funcs_weight[fw] += w
                w += 1

        # print(json.dumps(funcs_weight, indent=4))
        funcs_weight = sorted(funcs_weight.items(), key=itemgetter(1), reverse=True)
        # print(json.dumps(funcs_weight, indent=4))
        i = 0
        has_constructor = False
        constructor_name = ""
        for funcs in funcs_weight:
            if "constructor" in funcs[0]:
                constructor_name = funcs[0]
                has_constructor = True
                continue
            funcs_order[funcs[0]] = i
            i += 1

        # if not has_constructor:
        #     for itm in funcs_order:
        #         funcs_order[itm] -= 1

        if has_constructor:
            funcs_order[constructor_name] = i
        return i

    else:
        w = 0
        for key in funcs_order:
            funcs_order[key] = w
            w += 1
        return 0


def write_order(abis, _last):
    for node in abis:
        param_len = "0"
        try:
            param_len = str(len(node["inputs"]))
        except:
            pass
        # node["order"] = _last
        if node["type"] == "constructor":
            node["order"] = _last
        if node["type"] == "fallback":
            node["order"] = funcs_order["fallback," + node["stateMutability"] + ":" + param_len]
        if node["type"] == "function" and not node["constant"]:
            node["order"] = funcs_order[node["name"] + ":" + param_len]

    return json.dumps(abis)


if __name__ == '__main__':
    contract_name = para_input()
    if len(contract_name) == 0:
        print("Contract name is needed!")
        exit(1)
    contract = contract_name.split("/")[-1]
    contract = contract.split(".sol")[0]
    json_name = contract_name + ".json"
    json_content = {}

    with open(json_name, "r") as f:
        try:
            jsons = json.load(f)
        except:
            exit(1)

        json_content = jsons
        init_fdList(json.loads(jsons["contracts"][contract_name + ":" + contract]["abi"]))
        # print(json.dumps(json.loads(jsons["contracts"][contract_name + ":" + contract]["abi"]), indent=4))
        # print(funcs_order)

        ast_nodes = jsons["sources"][contract_name]["AST"]["children"]
        for anode in ast_nodes:
            attribute = anode["attributes"]
            if "name" in attribute.keys() and attribute["name"] == contract \
                    and "contractKind" in attribute.keys() and attribute["contractKind"] == "contract":
                ast_nodes = anode["children"]
                break
    f.close()

    init_paramList(ast_nodes)
    # print(param_list)

    if len(param_list.keys()) != 0:

        get_dataDependency(ast_nodes, "ModifierDefinition", modifier_dataDependency)
        # print(json.dumps(modifier_dataDependency, indent=4))
        m_dataDependency(ast_nodes, True)
        # print(json.dumps(funcs_dataDependency, indent=4))
        get_dataDependency(ast_nodes, "FunctionDefinition", funcs_dataDependency)
        # print(json.dumps(funcs_dataDependency, indent=4))
        m_dataDependency(ast_nodes, False)
        # print(json.dumps(funcs_dataDependency, indent=4))
        replace_internalCall()
    # print(json.dumps(funcs_dataDependency, indent=4))

    last_fi = get_funcsOrder()
    print(funcs_order)

    json_content["contracts"][contract_name + ":" + contract]["abi"] = \
        write_order(json.loads(json_content["contracts"][contract_name + ":" + contract]["abi"]), last_fi)
    # print(json.dumps(json.loads(json_content["contracts"][contract_name + ":" + contract]["abi"]), indent=4))


    with open(json_name, "w") as r:
        json.dump(json_content, r)
    r.close()
