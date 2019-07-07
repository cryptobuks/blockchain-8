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
    UniValue request(UniValue::VOBJ); // 构造对象类型的请求
    request.push_back(Pair("method", strMethod)); // 加入请求方法名
    request.push_back(Pair("params", params)); // 加入请求方法对应的参数
    request.push_back(Pair("id", id)); // 加入请求 id
    return request.write() + "\n"; // 格式化字符串
}

UniValue JSONRPCReplyObj(const UniValue& result, const UniValue& error, const UniValue& id)
{
    UniValue reply(UniValue::VOBJ); // 构造对象类型的 JSON 对象
    if (!error.isNull()) // 若存在错误
        reply.push_back(Pair("result", NullUniValue)); // 返回空结果
    else // 否则
        reply.push_back(Pair("result", result)); // 追加响应的结果
    reply.push_back(Pair("error", error)); // 增加错误字段
    reply.push_back(Pair("id", id)); // 增加 id 字段
    return reply; // 返回响应对象
}

string JSONRPCReply(const UniValue& result, const UniValue& error, const UniValue& id)
{
    UniValue reply = JSONRPCReplyObj(result, error, id); // 转调 JSONRPC 响应对象
    return reply.write() + "\n"; // 结果转换为字符串，拼接换行后返回
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
    boost::filesystem::path path(GetArg("-rpccookiefile", COOKIEAUTH_FILE)); // cookie 文件名，默认为 ".cookie"
    if (!path.is_complete()) path = GetDataDir() / path; // 路径拼接，获取 cookie 文件路径名
    return path;
}

bool GenerateAuthCookie(std::string *cookie_out)
{
    unsigned char rand_pwd[32];
    GetRandBytes(rand_pwd, 32); // 生成随机数
    std::string cookie = COOKIEAUTH_USER + ":" + EncodeBase64(&rand_pwd[0],32); // 拼接 cookie 字符串

    /** the umask determines what permissions are used to create this file -
     * these are set to 077 in init.cpp unless overridden with -sysperms.
     */ // 掩码确定用于创建文件的权限，在 init.cpp 中设置为 077，除非使用 -sysperms 选项覆盖。
    std::ofstream file;
    boost::filesystem::path filepath = GetAuthCookieFile(); // 获取验证 cookie 文件路径
    file.open(filepath.string().c_str()); // 打开文件
    if (!file.is_open()) {
        LogPrintf("Unable to open cookie authentication file %s for writing\n", filepath.string());
        return false;
    }
    file << cookie; // 把 cookie 写入 cookie 文件中
    file.close(); // 关闭并刷新文件输出流缓冲区
    LogPrintf("Generated RPC authentication cookie %s\n", filepath.string());

    if (cookie_out)
        *cookie_out = cookie; // 内存 cookie
    return true; // 成功返回 true
}

bool GetAuthCookie(std::string *cookie_out)
{
    std::ifstream file;
    std::string cookie;
    boost::filesystem::path filepath = GetAuthCookieFile(); // 获取 cookie 文件路径名
    file.open(filepath.string().c_str());
    if (!file.is_open())
        return false;
    std::getline(file, cookie); // 获取 cookie 文件第一行
    file.close();

    if (cookie_out)
        *cookie_out = cookie; // 传出 cookie 字符串
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

