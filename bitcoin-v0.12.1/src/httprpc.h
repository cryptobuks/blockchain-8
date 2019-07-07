// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HTTPRPC_H
#define BITCOIN_HTTPRPC_H

#include <string>
#include <map>

class HTTPRequest;

/** Start HTTP RPC subsystem.
 * Precondition; HTTP and RPC has been started.
 */ // 启动 HTTP RPC 子系统。前提：HTTP 和 RPC 已经启动。
bool StartHTTPRPC();
/** Interrupt HTTP RPC subsystem.
 */ // 中断 HTTP RPC 子系统。
void InterruptHTTPRPC();
/** Stop HTTP RPC subsystem.
 * Precondition; HTTP and RPC has been stopped.
 */ // 停止 HTTP RPC 子系统。前提：HTTP 和 RPC 已经停止。
void StopHTTPRPC();

/** Start HTTP REST subsystem.
 * Precondition; HTTP and RPC has been started.
 */ // 启动 HTTP REST 子系统。前提：HTTP 和 RPC 已经启动。
bool StartREST();
/** Interrupt RPC REST subsystem.
 */ // 中断 RPC REST 子系统。
void InterruptREST();
/** Stop HTTP REST subsystem.
 * Precondition; HTTP and RPC has been stopped.
 */ // 停止 RPC REST 子系统。前提：HTTP 和 RPC 已经停止。
void StopREST();

#endif
