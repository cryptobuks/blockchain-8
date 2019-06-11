#include "httprpc.h"

#include "base58.h"
#include "chainparams.h"
#include "httpserver.h"
#include "rpcprotocol.h"
#include "rpcserver.h"
#include "random.h"
#include "sync.h"
#include "util.h"
#include "utilstrencodings.h"
#include "ui_interface.h"
#include "crypto/hmac_sha256.h"
#include <stdio.h>
#include "utilstrencodings.h"

#include <boost/algorithm/string.hpp> // boost::trim
#include <boost/foreach.hpp> //BOOST_FOREACH

/** WWW-Authenticate to present with 401 Unauthorized response */
static const char* WWW_AUTH_HEADER_DATA = "Basic realm=\"jsonrpc\"";

/** Simple one-shot callback timer to be used by the RPC mechanism to e.g.
 * re-lock the wellet.
 */
class HTTPRPCTimer : public RPCTimerBase
{
public:
    HTTPRPCTimer(struct event_base* eventBase, boost::function<void(void)>& func, int64_t millis) :
        ev(eventBase, false, func)
    {
        struct timeval tv;
        tv.tv_sec = millis/1000;
        tv.tv_usec = (millis%1000)*1000;
        ev.trigger(&tv);
    }
private:
    HTTPEvent ev;
};

class HTTPRPCTimerInterface : public RPCTimerInterface // HTTPRPC 定时器接口类
{
public:
    HTTPRPCTimerInterface(struct event_base* base) : base(base)
    {
    }
    const char* Name()
    {
        return "HTTP";
    }
    RPCTimerBase* NewTimer(boost::function<void(void)>& func, int64_t millis)
    {
        return new HTTPRPCTimer(base, func, millis); // 在指定时间后执行 func 一次
    }
private:
    struct event_base* base;
};


/* Pre-base64-encoded authentication token */
static std::string strRPCUserColonPass; // base64 预编码的身份验证令牌
/* Stored RPC timer interface (for unregistration) */ // 存储的 RPC 定时器接口（用于解注册）
static HTTPRPCTimerInterface* httpRPCTimerInterface = 0;

static void JSONErrorReply(HTTPRequest* req, const UniValue& objError, const UniValue& id)
{
    // Send error reply from json-rpc error object
    int nStatus = HTTP_INTERNAL_SERVER_ERROR;
    int code = find_value(objError, "code").get_int();

    if (code == RPC_INVALID_REQUEST)
        nStatus = HTTP_BAD_REQUEST;
    else if (code == RPC_METHOD_NOT_FOUND)
        nStatus = HTTP_NOT_FOUND;

    std::string strReply = JSONRPCReply(NullUniValue, objError, id);

    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(nStatus, strReply);
}

//This function checks username and password against -rpcauth
//entries from config file. // 该函数根据配置文件中 -rpcauth 选项来检查用户名和密码
static bool multiUserAuthorized(std::string strUserPass)
{    
    if (strUserPass.find(":") == std::string::npos) { // 若未找到冒号
        return false; // 返回 false，表示验证失败
    } // 若找到
    std::string strUser = strUserPass.substr(0, strUserPass.find(":")); // 获取用户名
    std::string strPass = strUserPass.substr(strUserPass.find(":") + 1); // 获取密码

    if (mapMultiArgs.count("-rpcauth") > 0) { // 若 -rpcauth 选项指定了值
        //Search for multi-user login/pass "rpcauth" from config // 从配置文件中搜索多用户登陆/密码的“验证信息”
        BOOST_FOREACH(std::string strRPCAuth, mapMultiArgs["-rpcauth"]) // 遍历 -rpcauth 选项对应的值
        { // -rpcauth 格式：<USERNAME>:<SALT>$<HASH>
            std::vector<std::string> vFields; // 保存 3 个域
            boost::split(vFields, strRPCAuth, boost::is_any_of(":$")); // 根据 ":$" 分割单个验证信息
            if (vFields.size() != 3) {
                //Incorrect formatting in config file // 配置文件的格式不正确
                continue; // 跳过
            }

            std::string strName = vFields[0]; // 获取用户名
            if (!TimingResistantEqual(strName, strUser)) { // 对比验证用户名
                continue;
            }

            std::string strSalt = vFields[1]; // 获取盐值
            std::string strHash = vFields[2]; // 获取哈希值

            unsigned int KEY_SIZE = 32;
            unsigned char *out = new unsigned char[KEY_SIZE]; // 创建 256 位的堆对象
            
            CHMAC_SHA256(reinterpret_cast<const unsigned char*>(strSalt.c_str()), strSalt.size()).Write(reinterpret_cast<const unsigned char*>(strPass.c_str()), strPass.size()).Finalize(out); // DSHA256
            std::vector<unsigned char> hexvec(out, out+KEY_SIZE); // 初始化 256 为的数据
            std::string strHashFromPass = HexStr(hexvec); // 转换为 16 进制字符串

            if (TimingResistantEqual(strHashFromPass, strHash)) { // 对比哈希值
                return true; // 验证成功，返回 true
            }
        }
    } // 验证失败
    return false; // 返回 false
}

static bool RPCAuthorized(const std::string& strAuth)
{
    if (strRPCUserColonPass.empty()) // Belt-and-suspenders measure if InitRPCAuthentication was not called
        return false; // 若未调用 InitRPCAuthentication 初始化 strRPCUserColonPass，则直接返回 false 表示验证失败
    if (strAuth.substr(0, 6) != "Basic ") // 若验证信息前 6 个字符非 "Basic "
        return false; // 直接返回 false 表示验证失败
    std::string strUserPass64 = strAuth.substr(6); // 截取从下标为 6 的字符开始的字串
    boost::trim(strUserPass64); // 去除原字符串头尾的空格
    std::string strUserPass = DecodeBase64(strUserPass64); // base64 解码
    
    //Check if authorized under single-user field // 检查是否在单用户字段下授权
    if (TimingResistantEqual(strUserPass, strRPCUserColonPass)) {
        return true; // 验证成功返回 true
    } // 否则
    return multiUserAuthorized(strUserPass); // 进行多用户授权检测
}

static bool HTTPReq_JSONRPC(HTTPRequest* req, const std::string &) // HTTP 请求处理函数
{
    // JSONRPC handles only POST // 1.JSONRPC 仅处理 POST 类型 HTTP 请求
    if (req->GetRequestMethod() != HTTPRequest::POST) { // 若非 POST 类型的请求
        req->WriteReply(HTTP_BAD_METHOD, "JSONRPC server handles only POST requests"); // 反馈信息
        return false; // 直接退出并返回 false
    }
    // Check authorization // 2.检查授权
    std::pair<bool, std::string> authHeader = req->GetHeader("authorization"); // 获取头部授权字段
    if (!authHeader.first) { // 若不存在
        req->WriteHeader("WWW-Authenticate", WWW_AUTH_HEADER_DATA);
        req->WriteReply(HTTP_UNAUTHORIZED);
        return false; // 退出并返回 false
    }

    if (!RPCAuthorized(authHeader.second)) { // 对获取授权信息进行验证
        LogPrintf("ThreadRPCServer incorrect password attempt from %s\n", req->GetPeer().ToString());

        /* Deter brute-forcing // 阻止暴力
           If this results in a DoS the user really // 如果这导致 DoS，用户实际上不应该暴露其端口。
           shouldn't have their RPC port exposed. */
        MilliSleep(250); // 睡 250ms

        req->WriteHeader("WWW-Authenticate", WWW_AUTH_HEADER_DATA);
        req->WriteReply(HTTP_UNAUTHORIZED);
        return false;
    }

    JSONRequest jreq; // JSON 请求对象
    try {
        // Parse request // 3.解析请求
        UniValue valRequest; // 构造一个 JSON 对象
        if (!valRequest.read(req->ReadBody())) // 获取请求体
            throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");

        std::string strReply; // 4.响应内容字符串
        // singleton request // 4.1.单例请求
        if (valRequest.isObject()) { // 请求体是一个对象
            jreq.parse(valRequest); // 解析请求，放入 JSON 请求对象中

            UniValue result = tableRPC.execute(jreq.strMethod, jreq.params); // 传入相应的参数执行方法并获取响应结果

            // Send reply // 发送响应
            strReply = JSONRPCReply(result, NullUniValue, jreq.id); // 包装为 JSONRPC 响应内容字符串

        // array of requests // 请求数组
        } else if (valRequest.isArray()) // 4.2.数组
            strReply = JSONRPCExecBatch(valRequest.get_array()); // 批量处理并获取请求的响应内容字符串
        else
            throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");

        req->WriteHeader("Content-Type", "application/json"); // 5.写入响应头
        req->WriteReply(HTTP_OK, strReply); // 写入状态码和响应内容字符串
    } catch (const UniValue& objError) {
        JSONErrorReply(req, objError, jreq.id);
        return false;
    } catch (const std::exception& e) {
        JSONErrorReply(req, JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
        return false;
    }
    return true; // 6.成功返回 true
}

static bool InitRPCAuthentication()
{
    if (mapArgs["-rpcpassword"] == "")
    { // 密码为空
        LogPrintf("No rpcpassword set - using random cookie authentication\n");
        if (!GenerateAuthCookie(&strRPCUserColonPass)) { // 生成 cookie 字符串
            uiInterface.ThreadSafeMessageBox(
                _("Error: A fatal internal error occurred, see debug.log for details"), // Same message as AbortNode
                "", CClientUIInterface::MSG_ERROR);
            return false;
        }
    } else { // 密码非空
        LogPrintf("Config options rpcuser and rpcpassword will soon be deprecated. Locally-run instances may remove rpcuser to use cookie-based auth, or may be replaced with rpcauth. Please see share/rpcuser for rpcauth auth generation.\n");
        strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"]; // 拼接 RPC "user:pass" 字符串
    }
    return true;
}

bool StartHTTPRPC()
{
    LogPrint("rpc", "Starting HTTP RPC server\n");
    if (!InitRPCAuthentication()) // 1.初始化 RPC 身份验证（rpc "用户名:密码"）
        return false;

    RegisterHTTPHandler("/", true, HTTPReq_JSONRPC); // 2.注册 http url 处理函数

    assert(EventBase()); // 返回 event_base 对象指针
    httpRPCTimerInterface = new HTTPRPCTimerInterface(EventBase()); // 3.创建 http 定时器接口对象
    RPCRegisterTimerInterface(httpRPCTimerInterface); // 并注册 RPC 定时器接口
    return true; // 成功返回 true
}

void InterruptHTTPRPC()
{
    LogPrint("rpc", "Interrupting HTTP RPC server\n");
}

void StopHTTPRPC()
{
    LogPrint("rpc", "Stopping HTTP RPC server\n");
    UnregisterHTTPHandler("/", true);
    if (httpRPCTimerInterface) {
        RPCUnregisterTimerInterface(httpRPCTimerInterface);
        delete httpRPCTimerInterface;
        httpRPCTimerInterface = 0;
    }
}
