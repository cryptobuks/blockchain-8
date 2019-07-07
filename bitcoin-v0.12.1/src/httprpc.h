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
 */ // ���� HTTP RPC ��ϵͳ��ǰ�᣺HTTP �� RPC �Ѿ�������
bool StartHTTPRPC();
/** Interrupt HTTP RPC subsystem.
 */ // �ж� HTTP RPC ��ϵͳ��
void InterruptHTTPRPC();
/** Stop HTTP RPC subsystem.
 * Precondition; HTTP and RPC has been stopped.
 */ // ֹͣ HTTP RPC ��ϵͳ��ǰ�᣺HTTP �� RPC �Ѿ�ֹͣ��
void StopHTTPRPC();

/** Start HTTP REST subsystem.
 * Precondition; HTTP and RPC has been started.
 */ // ���� HTTP REST ��ϵͳ��ǰ�᣺HTTP �� RPC �Ѿ�������
bool StartREST();
/** Interrupt RPC REST subsystem.
 */ // �ж� RPC REST ��ϵͳ��
void InterruptREST();
/** Stop HTTP REST subsystem.
 * Precondition; HTTP and RPC has been stopped.
 */ // ֹͣ RPC REST ��ϵͳ��ǰ�᣺HTTP �� RPC �Ѿ�ֹͣ��
void StopREST();

#endif
