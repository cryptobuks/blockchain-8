// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparamsbase.h"
#include "clientversion.h"
#include "rpcclient.h"
#include "rpcprotocol.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/filesystem/operations.hpp>
#include <stdio.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>

#include <univalue.h>

using namespace std;

static const char DEFAULT_RPCCONNECT[] = "127.0.0.1";
static const int DEFAULT_HTTP_CLIENT_TIMEOUT=900;

std::string HelpMessageCli()
{
    string strUsage;
    strUsage += HelpMessageGroup(_("Options:"));
    strUsage += HelpMessageOpt("-?", _("This help message"));
    strUsage += HelpMessageOpt("-conf=<file>", strprintf(_("Specify configuration file (default: %s)"), BITCOIN_CONF_FILENAME));
    strUsage += HelpMessageOpt("-datadir=<dir>", _("Specify data directory"));
    AppendParamsHelpMessages(strUsage);
    strUsage += HelpMessageOpt("-rpcconnect=<ip>", strprintf(_("Send commands to node running on <ip> (default: %s)"), DEFAULT_RPCCONNECT));
    strUsage += HelpMessageOpt("-rpcport=<port>", strprintf(_("Connect to JSON-RPC on <port> (default: %u or testnet: %u)"), BaseParams(CBaseChainParams::MAIN).RPCPort(), BaseParams(CBaseChainParams::TESTNET).RPCPort()));
    strUsage += HelpMessageOpt("-rpcwait", _("Wait for RPC server to start"));
    strUsage += HelpMessageOpt("-rpcuser=<user>", _("Username for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcpassword=<pw>", _("Password for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcclienttimeout=<n>", strprintf(_("Timeout during HTTP requests (default: %d)"), DEFAULT_HTTP_CLIENT_TIMEOUT));

    return strUsage;
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:

    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}

};

static bool AppInitRPC(int argc, char* argv[]) // 2.0.应用程序初始化远程过程调用
{
    //
    // Parameters
    //
    ParseParameters(argc, argv); // 2.1.解析参数
    if (argc<2 || mapArgs.count("-?") || mapArgs.count("-h") || mapArgs.count("-help") || mapArgs.count("-version")) { // 2.2.帮助和版本信息
        std::string strUsage = _("Bitcoin Core RPC client version") + " " + FormatFullVersion() + "\n";
        if (!mapArgs.count("-version")) {
            strUsage += "\n" + _("Usage:") + "\n" +
                  "  bitcoin-cli [options] <command> [params]  " + _("Send command to Bitcoin Core") + "\n" +
                  "  bitcoin-cli [options] help                " + _("List commands") + "\n" +
                  "  bitcoin-cli [options] help <command>      " + _("Get help for a command") + "\n";

            strUsage += "\n" + HelpMessageCli();
        }

        fprintf(stdout, "%s", strUsage.c_str());
        return false;
    }
    if (!boost::filesystem::is_directory(GetDataDir(false))) { // 2.3.检查数据目录
        fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
        return false;
    }
    try {
        ReadConfigFile(mapArgs, mapMultiArgs); // 2.4.读配置文件
    } catch (const std::exception& e) {
        fprintf(stderr,"Error reading configuration file: %s\n", e.what());
        return false;
    }
    // Check for -testnet or -regtest parameter (BaseParams() calls are only valid after this clause)
    try {
        SelectBaseParams(ChainNameFromCommandLine()); // 2.5.根据链名选择链基础参数（RPC 端口、数据目录名）
    } catch (const std::exception& e) {
        fprintf(stderr, "Error: %s\n", e.what());
        return false;
    }
    if (GetBoolArg("-rpcssl", false))
    {
        fprintf(stderr, "Error: SSL mode for RPC (-rpcssl) is no longer supported.\n");
        return false;
    }
    return true;
}


/** Reply structure for request_done to fill in */
struct HTTPReply // 用于 request_done 填充的响应结构
{
    int status;
    std::string body;
};

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == NULL) {
        /* If req is NULL, it means an error occurred while connecting, but
         * I'm not sure how to find out which one. We also don't really care.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req); // status code

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size); // 获取响应的数据
        if (data)
            reply->body = std::string(data, size); // 构建 HTTP 响应体
        evbuffer_drain(buf, size); // 消耗函数，清除已读数据
    }
}

UniValue CallRPC(const string& strMethod, const UniValue& params)
{
    std::string host = GetArg("-rpcconnect", DEFAULT_RPCCONNECT); // 远程过程调用 IP 地址，默认本机环回 IP
    int port = GetArg("-rpcport", BaseParams().RPCPort()); // 远程过程调用端口，默认基础参数中的 RPC 端口

    // Create event base // 创建事件库对象
    struct event_base *base = event_base_new(); // TODO RAII
    if (!base)
        throw runtime_error("cannot create event_base");

    // Synchronously look up hostname // 同步查找主机名
    struct evhttp_connection *evcon = evhttp_connection_base_new(base, NULL, host.c_str(), port); // TODO RAII
    if (evcon == NULL)
        throw runtime_error("create connection failed");
    evhttp_connection_set_timeout(evcon, GetArg("-rpcclienttimeout", DEFAULT_HTTP_CLIENT_TIMEOUT)); // 远程过程调用客户端连接超时，默认 900 s

    HTTPReply response; // HTTP 响应（包含状态和内容）
    struct evhttp_request *req = evhttp_request_new(http_request_done, (void*)&response); // TODO RAII // 新建一个请求对象（头 + 参数）
    if (req == NULL)
        throw runtime_error("create http request failed");

    // Get credentials // 获取凭证
    std::string strRPCUserColonPass; // 用于保存用户名和密码
    if (mapArgs["-rpcpassword"] == "") { // 未提供密码
        // Try fall back to cookie-based authentication if no password is provided
        if (!GetAuthCookie(&strRPCUserColonPass)) { // 获取 cookie："cookie 授权用户名:password"
            throw runtime_error(strprintf(
                _("Could not locate RPC credentials. No authentication cookie could be found, and no rpcpassword is set in the configuration file (%s)"),
                    GetConfigFile().string().c_str()));

        }
    } else {
        strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"]; // username:password
    }

    struct evkeyvalq *output_headers = evhttp_request_get_output_headers(req); // 获取并构造请求的头
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str()); // 添加请求的主机
    evhttp_add_header(output_headers, "Connection", "close"); // 关闭长连接（即请求结束后连接就断掉）
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str()); // 添加授权（用户名 + 密码）

    // Attach request data // 获取请求数据
    std::string strRequest = JSONRPCRequest(strMethod, params, 1); // RPC 请求参数使用 Json 封装
    struct evbuffer * output_buffer = evhttp_request_get_output_buffer(req); // 获取请求的输出缓存
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size()); // 添加请求的参数到输出缓存

    int r = evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/"); // 发送 POST 请求
    if (r != 0) { // 发送成功，返回值为 0
        evhttp_connection_free(evcon);
        event_base_free(base);
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base); // 事件调度循环，类似于 event_base_loop，循环等待事件并通知事件发生
    evhttp_connection_free(evcon); // 释放 HTTP 连接
    event_base_free(base); // 释放与事件库对象 event_base 关联的所有内存

    if (response.status == 0) // 响应状态码为 0，表示无法连接到服务器
        throw CConnectionFailed("couldn't connect to server");
    else if (response.status == HTTP_UNAUTHORIZED) // 401 表示未授权，即 RPC 用户名或密码不正确
        throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR) // 大于等于 400 表示服务器返回错误
        throw runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty()) // 响应体为空，抛出异常
        throw runtime_error("no response from server");

    // Parse reply // 解析响应
    UniValue valReply(UniValue::VSTR); // 构造字符串类型响应对象
    if (!valReply.read(response.body)) // 读入响应的内容 pending
        throw runtime_error("couldn't parse reply from server");
    const UniValue& reply = valReply.get_obj(); // pending
    if (reply.empty())
        throw runtime_error("expected reply to have result, error and id properties");

    return reply;
}

int CommandLineRPC(int argc, char *argv[]) // 3.0.命令行远程过程调用
{
    string strPrint;
    int nRet = 0;
    try {
        // Skip switches
        while (argc > 1 && IsSwitchChar(argv[1][0])) { // 跳过带有 '-' 或 '/' 前缀的参数
            argc--;
            argv++;
        }

        // Method
        if (argc < 2) // 没有加命令行参数
            throw runtime_error("too few parameters"); // 抛出异常
        string strMethod = argv[1]; // 方法名

        // Parameters default to strings
        std::vector<std::string> strParams(&argv[2], &argv[argc]); // 方法对应的参数（第一个，最后一个）
        UniValue params = RPCConvertValues(strMethod, strParams); // 参数打包

        // Execute and handle connection failures with -rpcwait
        const bool fWait = GetBoolArg("-rpcwait", false); // 远程过程调用等待（调用失败后循环再次调用），默认关闭
        do {
            try {
                const UniValue reply = CallRPC(strMethod, params); // 调用 RPC（HTTP 请求），并获取响应

                // Parse reply
                const UniValue& result = find_value(reply, "result"); // 解析响应结果
                const UniValue& error  = find_value(reply, "error"); // 解析响应错误信息

                if (!error.isNull()) {
                    // Error
                    int code = error["code"].get_int();
                    if (fWait && code == RPC_IN_WARMUP)
                        throw CConnectionFailed("server in warmup");
                    strPrint = "error: " + error.write();
                    nRet = abs(code);
                    if (error.isObject())
                    {
                        UniValue errCode = find_value(error, "code");
                        UniValue errMsg  = find_value(error, "message");
                        strPrint = errCode.isNull() ? "" : "error code: "+errCode.getValStr()+"\n";

                        if (errMsg.isStr())
                            strPrint += "error message:\n"+errMsg.get_str();
                    }
                } else {
                    // Result
                    if (result.isNull()) // 结果为空
                        strPrint = "";
                    else if (result.isStr()) // 结果是字符串类型
                        strPrint = result.get_str(); // 获取字符串类型的结果
                    else // 非空 且 非字符串类型的结果
                        strPrint = result.write(2); // 格式化缩进
                }
                // Connection succeeded, no need to retry.
                break; // 连接（请求、响应）成功，不需要重试
            }
            catch (const CConnectionFailed&) {
                if (fWait)
                    MilliSleep(1000);
                else
                    throw;
            }
        } while (fWait);
    }
    catch (const boost::thread_interrupted&) {
        throw;
    }
    catch (const std::exception& e) {
        strPrint = string("error: ") + e.what();
        nRet = EXIT_FAILURE;
    }
    catch (...) {
        PrintExceptionContinue(NULL, "CommandLineRPC()");
        throw;
    }

    if (strPrint != "") { // 响应字符串非空
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str()); // 输出响应结果到屏幕（标准输出 或 标准错误）
    }
    return nRet;
}

int main(int argc, char* argv[]) // 0.获取（远程过程调用）命令行参数
{
    SetupEnvironment(); // 1.设置运行环境（同 bitcoind）
    if (!SetupNetworking()) { // 设置 windows socket
        fprintf(stderr, "Error: Initializing networking failed\n");
        exit(1);
    }

    try {
        if(!AppInitRPC(argc, argv)) // 2.应用程序初始化远程过程调用（参数、帮助、数据目录、配置文件、RPC 端口）
            return EXIT_FAILURE;
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitRPC()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInitRPC()");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    try {
        ret = CommandLineRPC(argc, argv); // 3.命令行远程过程调用
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "CommandLineRPC()");
    } catch (...) {
        PrintExceptionContinue(NULL, "CommandLineRPC()");
    }
    return ret;
}
