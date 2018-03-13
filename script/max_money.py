#!/usr/bin/python

start_block_reward = 50

reward_interval = 210000

def max_money():
    # 1 BTC = 1 0000 0000 Satoshis
    current_reward = 50 * 10**8
    total_money = 0
    while current_reward > 0:
        total_money += reward_interval * current_reward
        current_reward /= 2
    return total_money

if __name__ == "__main__":
    print "Total BTC to ever be created: ", max_money(), " Satoshis" # python: 2099999997690000
    #print("Total BTC to ever be created: ", max_money(), " Satoshis") # python3: 2100000000000000.0
