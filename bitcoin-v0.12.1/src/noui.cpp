// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "noui.h"

#include "ui_interface.h"
#include "util.h"

#include <cstdio>
#include <stdint.h>
#include <string>

static bool noui_ThreadSafeMessageBox(const std::string& message, const std::string& caption, unsigned int style)
{
    bool fSecure = style & CClientUIInterface::SECURE; // ͨ����Ϣ���ͻ�ȡ��ȫ��־
    style &= ~CClientUIInterface::SECURE;

    std::string strCaption; // �ַ������ͱ���
    // Check for usage of predefined caption // ���Ԥ���������÷�
    switch (style) { // ��������ѡ����Ϣ����
    case CClientUIInterface::MSG_ERROR:
        strCaption += _("Error"); // �������
        break;
    case CClientUIInterface::MSG_WARNING:
        strCaption += _("Warning"); // �������
        break;
    case CClientUIInterface::MSG_INFORMATION:
        strCaption += _("Information"); // ��Ϣ����
        break;
    default:
        strCaption += caption; // Use supplied caption (can be empty) // ʹ���ṩ�ı��⣨����Ϊ�գ�
    }

    if (!fSecure) // ������ȫ
        LogPrintf("%s: %s\n", strCaption, message);
    fprintf(stderr, "%s: %s\n", strCaption.c_str(), message.c_str()); // �ַ���ƴ���ض��򵽱�׼����
    return false; // �ɹ����� false
}

static void noui_InitMessage(const std::string& message)
{
    LogPrintf("init message: %s\n", message); // ��¼��־
}

void noui_connect()
{
    // Connect bitcoind signal handlers // ���ӱ��رҺ��ķ����źŴ�����
    uiInterface.ThreadSafeMessageBox.connect(noui_ThreadSafeMessageBox); // 1.������ UI �̰߳�ȫ��Ϣ������+��Ϣ��
    uiInterface.InitMessage.connect(noui_InitMessage); // 2.������ UI ��ʼ����Ϣ
}
