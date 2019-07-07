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
    while (!fShutdown) // ѭ���ȴ��ر�����
    {
        MilliSleep(200); // ˯�� 200 ����
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
// Start // ���� // [C]:completed,[F]:finished,[P]:pending
//
bool AppInit(int argc, char* argv[]) // [P]3.0.Ӧ�ó����ʼ��
{
    boost::thread_group threadGroup; // ���߳�����󣬹�����̣߳����ɸ��ƺ��ƶ�
    CScheduler scheduler; // ����������

    bool fRet = false; // ������־�������ж�Ӧ�ó�������״̬����ʼ��Ϊ false����ʾδ����

    //
    // Parameters // ����
    //
    // If Qt is used, parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main() // ���ʹ�� Qt������ qt/bitcoin.cpp �ļ��� main �����н�������/�����ļ�
    ParseParameters(argc, argv); // [F]3.1.���������У�����̨���룩����

    // Process help and version before taking care about datadir // �ڹ�ע����Ŀ¼ǰ����������Ͱ汾
    if (mapArgs.count("-?") || mapArgs.count("-h") ||  mapArgs.count("-help") || mapArgs.count("-version")) // [P]3.2.0.�汾�Ͱ�����Ϣ��dirty δ�����
    {
        std::string strUsage = _("Bitcoin Core Daemon") + " " + _("version") + " " + FormatFullVersion() + "\n"; // 1.��ȡ�汾��Ϣ

        if (mapArgs.count("-version")) // 2.�汾��ɺͰ�����Ϣ��ѡ��
        {
            strUsage += LicenseInfo(); // 2.1.��ȡ���֤��Ϣ
        }
        else
        {
            strUsage += "\n" + _("Usage:") + "\n" +
                  "  bitcoind [options]                     " + _("Start Bitcoin Core Daemon") + "\n";

            strUsage += "\n" + HelpMessage(HMM_BITCOIND); // 2.2.��ȡ������Ϣ
        }

        fprintf(stdout, "%s", strUsage.c_str()); // 3.����Ϣ�������׼������˳�
        return false;
    }

    try
    {
        if (!boost::filesystem::is_directory(GetDataDir(false))) // [F]3.3.����Ŀ¼���Ȼ�ȡ������������ Ĭ��/ָ�� ���ִ���
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
            return false;
        }
        try
        {
            ReadConfigFile(mapArgs, mapMultiArgs); // [F]3.4.��ȡ�����ļ�
        } catch (const std::exception& e) {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            return false;
        }
        // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause) // ��� -testnet �� -regtest ������Params() ���þ������֮����Ч��
        try {
            SelectParams(ChainNameFromCommandLine()); // [F]3.5.ѡ�������������磩���������������������ʱ������
        } catch (const std::exception& e) {
            fprintf(stderr, "Error: %s\n", e.what());
            return false;
        }

        // Command-line RPC // [F]3.6.0.��������в���������
        bool fCommandLine = false; // �����д����־����ʼ��Ϊ false
        for (int i = 1; i < argc; i++) // 1.����ָ���������в���
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "bitcoin:")) // ����һ�������в�������'-'��'/'��ͷ
                fCommandLine = true; // �����д����־��Ϊ true

        if (fCommandLine) // 2.�������в������ڴ���
        {
            fprintf(stderr, "Error: There is no RPC client functionality in bitcoind anymore. Use the bitcoin-cli utility instead.\n"); // ��ӡ����ԭ��
            exit(1); // �˳�����
        }
#ifndef WIN32 // [F]3.7.0.Uinx/Linux ���ػ����̺�̨��
        fDaemon = GetBoolArg("-daemon", false); // 1.��̨����־��Ĭ��Ϊ false
        if (fDaemon) // 2.�������˺�̨��ѡ����г���ĺ�̨��
        {
            fprintf(stdout, "Bitcoin server starting\n"); // ������ر�������������Ϣ����׼���

            // Daemonize // �ػ����̺�̨��
            pid_t pid = fork(); // 2.1.�����ӽ��̣�����ȡ���� id
            if (pid < 0) // ����
            {
                fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
                return false; // �˳�
            }
            if (pid > 0) // Parent process, pid is child process id // 2.2.�����̷����ӽ��̺�
            {
                return true; // ֱ���˳�
            }
            // Child process falls through to rest of initialization  // �ӽ��̣����� 0�������ʼ����ʣ�ಿ��

            pid_t sid = setsid(); // 2.3.�����»Ự
            if (sid < 0) // �Ự id ������ڵ��� 0
                fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
        }
#endif
        SoftSetBoolArg("-server", true); // [F]3.8.���������ѡ�Ĭ�Ͽ����������ں�������

        // Set this early so that parameter interactions go to console // �������ø���ʹ��������������̨
        InitLogging(); // [F]3.9.��ʼ����־��¼
        InitParameterInteraction(); // [P]3.10.��ʼ����������
        fRet = AppInit2(threadGroup, scheduler); // [P]3.11.Ӧ�ó����ʼ�� 2��������ڣ�
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }

    if (!fRet) // [F]3.12.����������־������Ӧ����
    {
        Interrupt(threadGroup); // ����ʧ��
        // threadGroup.join_all(); was left out intentionally here, because we didn't re-test all of
        // the startup-failure cases to make sure they don't result in a hang due to some
        // thread-blocking-waiting-for-another-thread-during-startup case
    } else {
        WaitForShutdown(&threadGroup); // �����ɹ���ѭ���ȴ��ر�
    }
    Shutdown(); // [P]3.13.�ر�

    return fRet;
}

int main(int argc, char* argv[]) // [P]0.�������
{
    SetupEnvironment(); // [F]1.���ó������л��������ػ�����

    // Connect bitcoind signal handlers
    noui_connect(); // [P]2.�� UI ���ӣ������źŴ�����

    return (AppInit(argc, argv) ? 0 : 1); // [P]3.Ӧ�ó����ʼ������ʼ��������
}
