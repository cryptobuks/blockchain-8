#!/usr/bin/python3

import json
import requests
import time

def json_rpc(method, params):
    payload = json.dumps({"method": method, "params": params})
    response = requests.request("POST", url, data=payload, auth=auth)
    return response.json()

def getinfo():
    return json_rpc("getinfo", [])

def getbestblockinfo():
    ret = json_rpc("getbestblockhash", [])
    bestblockhash = ret["result"]
    return json_rpc("getblock", [bestblockhash])

def getdifficulty():
    return json_rpc("getdifficulty", [])

def getnetworkhashps():
    return json_rpc("getnetworkhashps", [])

def rpc_func():
    print("info:")
    print(getinfo())
    print("\nbestblockinfo:")
    print(getbestblockinfo())
    print("\ndifficulty:")
    print(getdifficulty())
    print("\nnetworkhashps:")
    print(getnetworkhashps())

if __name__ == "__main__":
    url = "http://127.0.0.1:8332"
    auth=("rpcuser", "rpcpassword")
    while (1):
        rpc_func()
        time.sleep(7)
