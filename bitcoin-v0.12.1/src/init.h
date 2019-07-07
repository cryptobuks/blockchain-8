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

extern CWallet* pwalletMain; // 钱包对象指针

void StartShutdown(); // 关闭比特币核心服务
bool ShutdownRequested(); // 获取当前是否请求关闭的状态
/** Interrupt threads */ // 打断线程
void Interrupt(boost::thread_group& threadGroup);
void Shutdown();
//!Initialize the logging infrastructure // 初始化日志记录基础结构
void InitLogging();
//!Parameter interaction: change current parameters depending on various rules // 参数交互：基于多种规则改变当前参数
void InitParameterInteraction();
bool AppInit2(boost::thread_group& threadGroup, CScheduler& scheduler); // 应用程序初始化（本物入口）

/** The help message mode determines what help message to show */ // 确定显示什么帮助信息的帮助信息模式
enum HelpMessageMode { // 帮助信息模式枚举
    HMM_BITCOIND, // 0
    HMM_BITCOIN_QT // 1
};

/** Help for options shared between UI and daemon (for -help) */ // 用于 UI 和守护进程间共享的帮助选项（用于 -help）
std::string HelpMessage(HelpMessageMode mode);
/** Returns licensing information (for -version) */ // 返回许可证信息（用于 -version）
std::string LicenseInfo();

#endif // BITCOIN_INIT_H
