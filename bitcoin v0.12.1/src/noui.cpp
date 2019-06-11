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
    bool fSecure = style & CClientUIInterface::SECURE; // 通过消息类型获取安全标志
    style &= ~CClientUIInterface::SECURE;

    std::string strCaption; // 字符串类型标题
    // Check for usage of predefined caption // 检查预定义标题的用法
    switch (style) { // 根据类型选择消息标题
    case CClientUIInterface::MSG_ERROR:
        strCaption += _("Error"); // 错误标题
        break;
    case CClientUIInterface::MSG_WARNING:
        strCaption += _("Warning"); // 警告标题
        break;
    case CClientUIInterface::MSG_INFORMATION:
        strCaption += _("Information"); // 信息标题
        break;
    default:
        strCaption += caption; // Use supplied caption (can be empty) // 使用提供的标题（可能为空）
    }

    if (!fSecure) // 若不安全
        LogPrintf("%s: %s\n", strCaption, message);
    fprintf(stderr, "%s: %s\n", strCaption.c_str(), message.c_str()); // 字符串拼接重定向到标准错误
    return false; // 成功返回 false
}

static void noui_InitMessage(const std::string& message)
{
    LogPrintf("init message: %s\n", message); // 记录日志
}

void noui_connect()
{
    // Connect bitcoind signal handlers // 连接比特币核心服务信号处理函数
    uiInterface.ThreadSafeMessageBox.connect(noui_ThreadSafeMessageBox); // 1.连接无 UI 线程安全消息框（类型+消息）
    uiInterface.InitMessage.connect(noui_InitMessage); // 2.连接无 UI 初始化消息
}
