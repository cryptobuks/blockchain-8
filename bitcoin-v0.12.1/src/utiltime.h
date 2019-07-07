// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTILTIME_H
#define BITCOIN_UTILTIME_H

#include <stdint.h>
#include <string>

int64_t GetTime(); // ��ȡ��ǰʱ�� ��
int64_t GetTimeMillis(); // ��ȡ��ǰʱ�� ����
int64_t GetTimeMicros(); // ��ȡ��ǰʱ�� ΢��
int64_t GetLogTimeMicros(); // ���� GetTimeMicros
void SetMockTime(int64_t nMockTimeIn); // ���� Mock ʱ��
void MilliSleep(int64_t n); // ˯ n ����

std::string DateTimeStrFormat(const char* pszFormat, int64_t nTime); // ��ʽ������ʱ��

#endif // BITCOIN_UTILTIME_H
