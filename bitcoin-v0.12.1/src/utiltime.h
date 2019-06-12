// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTILTIME_H
#define BITCOIN_UTILTIME_H

#include <stdint.h>
#include <string>

int64_t GetTime(); // 获取当前时间 秒
int64_t GetTimeMillis(); // 获取当前时间 毫秒
int64_t GetTimeMicros(); // 获取当前时间 微秒
int64_t GetLogTimeMicros(); // 调用 GetTimeMicros
void SetMockTime(int64_t nMockTimeIn); // 设置 Mock 时间
void MilliSleep(int64_t n); // 睡 n 毫秒

std::string DateTimeStrFormat(const char* pszFormat, int64_t nTime); // 格式化日期时间

#endif // BITCOIN_UTILTIME_H
