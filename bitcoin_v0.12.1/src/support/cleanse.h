// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SUPPORT_CLEANSE_H
#define BITCOIN_SUPPORT_CLEANSE_H

#include <stdlib.h>

void memory_cleanse(void *ptr, size_t len); // 清空敏感数据（写入随机数或纯 0）

#endif // BITCOIN_SUPPORT_CLEANSE_H
