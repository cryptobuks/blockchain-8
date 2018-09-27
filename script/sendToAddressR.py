#!/usr/bin/python3
#coding=utf-8

# 模拟短时间内大量交易

import os
import time

address = input("Please enter dest address: ")
amount = input("Please enter amount(recommend 0.1): ")

while True:
    os.system("bitcoin-cli sendtoaddress address amount")
    time.sleep(0.1) # for Ctrl+C
