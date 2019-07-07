// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include <string>

class CScheduler;
class CWallet;

namespace boost
{
class thread_group;
} // namespace boost

extern CWallet* pwalletMain; // Ǯ������ָ��

void StartShutdown(); // �رձ��رҺ��ķ���
bool ShutdownRequested(); // ��ȡ��ǰ�Ƿ�����رյ�״̬
/** Interrupt threads */ // ����߳�
void Interrupt(boost::thread_group& threadGroup);
void Shutdown();
//!Initialize the logging infrastructure // ��ʼ����־��¼�����ṹ
void InitLogging();
//!Parameter interaction: change current parameters depending on various rules // �������������ڶ��ֹ���ı䵱ǰ����
void InitParameterInteraction();
bool AppInit2(boost::thread_group& threadGroup, CScheduler& scheduler); // Ӧ�ó����ʼ����������ڣ�

/** The help message mode determines what help message to show */ // ȷ����ʾʲô������Ϣ�İ�����Ϣģʽ
enum HelpMessageMode { // ������Ϣģʽö��
    HMM_BITCOIND, // 0
    HMM_BITCOIN_QT // 1
};

/** Help for options shared between UI and daemon (for -help) */ // ���� UI ���ػ����̼乲��İ���ѡ����� -help��
std::string HelpMessage(HelpMessageMode mode);
/** Returns licensing information (for -version) */ // �������֤��Ϣ������ -version��
std::string LicenseInfo();

#endif // BITCOIN_INIT_H
