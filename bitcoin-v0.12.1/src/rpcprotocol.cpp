// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcprotocol.h"

#include "random.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "version.h"

#include <stdint.h>
#include <fstream>

using namespace std;

/**
 * JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
 * but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
 * unspecified (HTTP errors and contents of 'error').
 * 
 * 1.0 spec: http://json-rpc.org/wiki/specification
 * 1.2 spec: http://jsonrpc.org/historical/json-rpc-over-http.html
 */

string JSONRPCRequest(const string& strMethod, const UniValue& params, const UniValue& id)
{
    UniValue request(UniValue::VOBJ); // ����������͵�����
    request.push_back(Pair("method", strMethod)); // �������󷽷���
    request.push_back(Pair("params", params)); // �������󷽷���Ӧ�Ĳ���
    request.push_back(Pair("id", id)); // �������� id
    return request.write() + "\n"; // ��ʽ���ַ���
}

UniValue JSONRPCReplyObj(const UniValue& result, const UniValue& error, const UniValue& id)
{
    UniValue reply(UniValue::VOBJ); // ����������͵� JSON ����
    if (!error.isNull()) // �����ڴ���
        reply.push_back(Pair("result", NullUniValue)); // ���ؿս��
    else // ����
        reply.push_back(Pair("result", result)); // ׷����Ӧ�Ľ��
    reply.push_back(Pair("error", error)); // ���Ӵ����ֶ�
    reply.push_back(Pair("id", id)); // ���� id �ֶ�
    return reply; // ������Ӧ����
}

string JSONRPCReply(const UniValue& result, const UniValue& error, const UniValue& id)
{
    UniValue reply = JSONRPCReplyObj(result, error, id); // ת�� JSONRPC ��Ӧ����
    return reply.write() + "\n"; // ���ת��Ϊ�ַ�����ƴ�ӻ��к󷵻�
}

UniValue JSONRPCError(int code, const string& message)
{
    UniValue error(UniValue::VOBJ);
    error.push_back(Pair("code", code));
    error.push_back(Pair("message", message));
    return error;
}

/** Username used when cookie authentication is in use (arbitrary, only for
 * recognizability in debugging/logging purposes)
 */
static const std::string COOKIEAUTH_USER = "__cookie__";
/** Default name for auth cookie file */
static const std::string COOKIEAUTH_FILE = ".cookie";

boost::filesystem::path GetAuthCookieFile()
{
    boost::filesystem::path path(GetArg("-rpccookiefile", COOKIEAUTH_FILE)); // cookie �ļ�����Ĭ��Ϊ ".cookie"
    if (!path.is_complete()) path = GetDataDir() / path; // ·��ƴ�ӣ���ȡ cookie �ļ�·����
    return path;
}

bool GenerateAuthCookie(std::string *cookie_out)
{
    unsigned char rand_pwd[32];
    GetRandBytes(rand_pwd, 32); // ���������
    std::string cookie = COOKIEAUTH_USER + ":" + EncodeBase64(&rand_pwd[0],32); // ƴ�� cookie �ַ���

    /** the umask determines what permissions are used to create this file -
     * these are set to 077 in init.cpp unless overridden with -sysperms.
     */ // ����ȷ�����ڴ����ļ���Ȩ�ޣ��� init.cpp ������Ϊ 077������ʹ�� -sysperms ѡ��ǡ�
    std::ofstream file;
    boost::filesystem::path filepath = GetAuthCookieFile(); // ��ȡ��֤ cookie �ļ�·��
    file.open(filepath.string().c_str()); // ���ļ�
    if (!file.is_open()) {
        LogPrintf("Unable to open cookie authentication file %s for writing\n", filepath.string());
        return false;
    }
    file << cookie; // �� cookie д�� cookie �ļ���
    file.close(); // �رղ�ˢ���ļ������������
    LogPrintf("Generated RPC authentication cookie %s\n", filepath.string());

    if (cookie_out)
        *cookie_out = cookie; // �ڴ� cookie
    return true; // �ɹ����� true
}

bool GetAuthCookie(std::string *cookie_out)
{
    std::ifstream file;
    std::string cookie;
    boost::filesystem::path filepath = GetAuthCookieFile(); // ��ȡ cookie �ļ�·����
    file.open(filepath.string().c_str());
    if (!file.is_open())
        return false;
    std::getline(file, cookie); // ��ȡ cookie �ļ���һ��
    file.close();

    if (cookie_out)
        *cookie_out = cookie; // ���� cookie �ַ���
    return true;
}

void DeleteAuthCookie()
{
    try {
        boost::filesystem::remove(GetAuthCookieFile());
    } catch (const boost::filesystem::filesystem_error& e) {
        LogPrintf("%s: Unable to remove random auth cookie file: %s\n", __func__, e.what());
    }
}

