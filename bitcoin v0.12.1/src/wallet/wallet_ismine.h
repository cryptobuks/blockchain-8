// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLET_ISMINE_H
#define BITCOIN_WALLET_WALLET_ISMINE_H

#include "script/standard.h"

#include <stdint.h>

class CKeyStore;
class CScript;

/** IsMine() return codes */ // IsMine() 的返回码
enum isminetype
{
    ISMINE_NO = 0,
    //! Indicates that we dont know how to create a scriptSig that would solve this if we were given the appropriate private keys
    ISMINE_WATCH_UNSOLVABLE = 1, // 表示如果我们提供了适当的私钥，我们不知道如何创建一个解决该问题的脚本签名
    //! Indicates that we know how to create a scriptSig that would solve this if we were given the appropriate private keys
    ISMINE_WATCH_SOLVABLE = 2,
    ISMINE_WATCH_ONLY = ISMINE_WATCH_SOLVABLE | ISMINE_WATCH_UNSOLVABLE, // 3
    ISMINE_SPENDABLE = 4, // 可花费
    ISMINE_ALL = ISMINE_WATCH_ONLY | ISMINE_SPENDABLE // Watch-only 或 可花费
};
/** used for bitflags of isminetype */ // 用于 isminetype 的标志位
typedef uint8_t isminefilter; // 8 位

isminetype IsMine(const CKeyStore& keystore, const CScript& scriptPubKey); // 是我的
isminetype IsMine(const CKeyStore& keystore, const CTxDestination& dest); // 是我的

#endif // BITCOIN_WALLET_WALLET_ISMINE_H
