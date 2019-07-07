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

/** IsMine() return codes */ // IsMine() �ķ�����
enum isminetype
{
    ISMINE_NO = 0,
    //! Indicates that we dont know how to create a scriptSig that would solve this if we were given the appropriate private keys
    ISMINE_WATCH_UNSOLVABLE = 1, // ��ʾ��������ṩ���ʵ���˽Կ�����ǲ�֪����δ���һ�����������Ľű�ǩ��
    //! Indicates that we know how to create a scriptSig that would solve this if we were given the appropriate private keys
    ISMINE_WATCH_SOLVABLE = 2,
    ISMINE_WATCH_ONLY = ISMINE_WATCH_SOLVABLE | ISMINE_WATCH_UNSOLVABLE, // 3
    ISMINE_SPENDABLE = 4, // �ɻ���
    ISMINE_ALL = ISMINE_WATCH_ONLY | ISMINE_SPENDABLE // Watch-only �� �ɻ���
};
/** used for bitflags of isminetype */ // ���� isminetype �ı�־λ
typedef uint8_t isminefilter; // 8 λ

isminetype IsMine(const CKeyStore& keystore, const CScript& scriptPubKey); // ���ҵ�
isminetype IsMine(const CKeyStore& keystore, const CTxDestination& dest); // ���ҵ�

#endif // BITCOIN_WALLET_WALLET_ISMINE_H
