// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "clientversion.h"
#include "rpcserver.h"
#include "init.h"
#include "noui.h"
#include "scheduler.h"
#include "util.h"
#include "httpserver.h"
#include "httprpc.h"
#include "rpcserver.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include <stdio.h>

/* Introduction text for doxygen: */

/*! \mainpage Developer documentation
 *
 * \section intro_sec Introduction
 *
 * This is the developer documentation of the reference client for an experimental new digital currency called Bitcoin (https://www.bitcoin.org/),
 * which enables instant payments to anyone, anywhere in the world. Bitcoin uses peer-to-peer technology to operate
 * with no central authority: managing transactions and issuing money are carried out collectively by the network.
 *
 * The software is a community-driven open source project, released under the MIT license.
 *
 * \section Navigation
 * Use the buttons <code>Namespaces</code>, <code>Classes</code> or <code>Files</code> at the top of the page to start navigating the code.
 */

static bool fDaemon;

void WaitForShutdown(boost::thread_group* threadGroup)
{
    bool fShutdown = ShutdownRequested();
    // Tell the main threads to shutdown.
    while (!fShutdown) // 循环等待关闭请求
    {
        MilliSleep(200); // 睡眠 200 毫秒
        fShutdown = ShutdownRequested();
    }
    if (threadGroup)
    {
        Interrupt(*threadGroup);
        threadGroup->join_all();
    }
}

//////////////////////////////////////////////////////////////////////////////
//
// Start // 启动 // [C]:completed,[F]:finished,[P]:pending
//
bool AppInit(int argc, char* argv[]) // [P]3.0.应用程序初始化
{
    boost::thread_group threadGroup; // 空线程组对象，管理多线程，不可复制和移动
    CScheduler scheduler; // 调度器对象

    bool fRet = false; // 启动标志：用于判断应用程序启动状态，初始化为 false，表示未启动

    //
    // Parameters // 参数
    //
    // If Qt is used, parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main() // 如果使用 Qt，则在 qt/bitcoin.cpp 文件的 main 函数中解析参数/配置文件
    ParseParameters(argc, argv); // [F]3.1.解析命令行（控制台传入）参数

    // Process help and version before taking care about datadir // 在关注数据目录前，处理帮助和版本
    if (mapArgs.count("-?") || mapArgs.count("-h") ||  mapArgs.count("-help") || mapArgs.count("-version")) // [P]3.2.0.版本和帮助信息（dirty 未解决）
    {
        std::string strUsage = _("Bitcoin Core Daemon") + " " + _("version") + " " + FormatFullVersion() + "\n"; // 1.获取版本信息

        if (mapArgs.count("-version")) // 2.版本许可和帮助信息的选择
        {
            strUsage += LicenseInfo(); // 2.1.获取许可证信息
        }
        else
        {
            strUsage += "\n" + _("Usage:") + "\n" +
                  "  bitcoind [options]                     " + _("Start Bitcoin Core Daemon") + "\n";

            strUsage += "\n" + HelpMessage(HMM_BITCOIND); // 2.2.获取帮助信息
        }

        fprintf(stdout, "%s", strUsage.c_str()); // 3.把信息输出到标准输出并退出
        return false;
    }

    try
    {
        if (!boost::filesystem::is_directory(GetDataDir(false))) // [F]3.3.数据目录：先获取，若不存在则按 默认/指定 名字创建
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
            return false;
        }
        try
        {
            ReadConfigFile(mapArgs, mapMultiArgs); // [F]3.4.读取配置文件
        } catch (const std::exception& e) {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            return false;
        }
        // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause) // 检查 -testnet 或 -regtest 参数（Params() 调用尽在这句之后有效）
        try {
            SelectParams(ChainNameFromCommandLine()); // [F]3.5.选择区块链（网络）参数，创世区块程序启动时便生成
        } catch (const std::exception& e) {
            fprintf(stderr, "Error: %s\n", e.what());
            return false;
        }

        // Command-line RPC // [F]3.6.0.检测命令行参数完整性
        bool fCommandLine = false; // 命令行错误标志，初始化为 false
        for (int i = 1; i < argc; i++) // 1.遍历指定的命令行参数
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "bitcoin:")) // 若有一个命令行参数是以'-'或'/'开头
                fCommandLine = true; // 命令行错误标志置为 true

        if (fCommandLine) // 2.若命令行参数存在错误
        {
            fprintf(stderr, "Error: There is no RPC client functionality in bitcoind anymore. Use the bitcoin-cli utility instead.\n"); // 打印错误原因
            exit(1); // 退出程序
        }
#ifndef WIN32 // [F]3.7.0.Uinx/Linux 下守护进程后台化
        fDaemon = GetBoolArg("-daemon", false); // 1.后台化标志，默认为 false
        if (fDaemon) // 2.若开启了后台化选项，进行程序的后台化
        {
            fprintf(stdout, "Bitcoin server starting\n"); // 输出比特币正在启动的信息到标准输出

            // Daemonize // 守护进程后台化
            pid_t pid = fork(); // 2.1.派生子进程，并获取进程 id
            if (pid < 0) // 出错
            {
                fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
                return false; // 退出
            }
            if (pid > 0) // Parent process, pid is child process id // 2.2.父进程返回子进程号
            {
                return true; // 直接退出
            }
            // Child process falls through to rest of initialization  // 子进程，返回 0，进入初始化的剩余部分

            pid_t sid = setsid(); // 2.3.设置新会话
            if (sid < 0) // 会话 id 必须大于等于 0
                fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
        }
#endif
        SoftSetBoolArg("-server", true); // [F]3.8.软服务设置选项，默认开启，服务在后面启动

        // Set this early so that parameter interactions go to console
        InitLogging(); // [F]3.9.初始化日志记录，默认输出至 debug.log
        InitParameterInteraction(); // [P]3.10.初始化参数交互，说明部分参数规则（用法）
        fRet = AppInit2(threadGroup, scheduler); // [P]3.11.应用程序初始化 2（本物入口）
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }

    if (!fRet) // [F]3.12.根据启动标志做出相应处理
    {
        Interrupt(threadGroup); // 启动失败
        // threadGroup.join_all(); was left out intentionally here, because we didn't re-test all of
        // the startup-failure cases to make sure they don't result in a hang due to some
        // thread-blocking-waiting-for-another-thread-during-startup case
    } else {
        WaitForShutdown(&threadGroup); // 启动成功，循环等待关闭
    }
    Shutdown(); // [P]3.13.关闭

    return fRet;
}

int main(int argc, char* argv[]) // [P]0.程序入口
{
    SetupEnvironment(); // [F]1.设置程序运行环境：本地化处理

    // Connect bitcoind signal handlers
    noui_connect(); // [P]2.无 UI 连接：连接信号处理函数

    return (AppInit(argc, argv) ? 0 : 1); // [P]3.应用程序初始化：初始化并启动
}
