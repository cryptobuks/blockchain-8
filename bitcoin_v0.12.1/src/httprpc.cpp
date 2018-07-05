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

class HTTPRPCTimerInterface : public RPCTimerInterface
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
static std::string strRPCUserColonPass;
/* Stored RPC timer interface (for unregistration) */
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
//entries from config file.
static bool multiUserAuthorized(std::string strUserPass)
{    
    if (strUserPass.find(":") == std::string::npos) {
        return false;
    }
    std::string strUser = strUserPass.substr(0, strUserPass.find(":"));
    std::string strPass = strUserPass.substr(strUserPass.find(":") + 1);

    if (mapMultiArgs.count("-rpcauth") > 0) {
        //Search for multi-user login/pass "rpcauth" from config
        BOOST_FOREACH(std::string strRPCAuth, mapMultiArgs["-rpcauth"])
        {
            std::vector<std::string> vFields;
            boost::split(vFields, strRPCAuth, boost::is_any_of(":$"));
            if (vFields.size() != 3) {
                //Incorrect formatting in config file
                continue;
            }

            std::string strName = vFields[0];
            if (!TimingResistantEqual(strName, strUser)) {
                continue;
            }

            std::string strSalt = vFields[1];
            std::string strHash = vFields[2];

            unsigned int KEY_SIZE = 32;
            unsigned char *out = new unsigned char[KEY_SIZE]; 
            
            CHMAC_SHA256(reinterpret_cast<const unsigned char*>(strSalt.c_str()), strSalt.size()).Write(reinterpret_cast<const unsigned char*>(strPass.c_str()), strPass.size()).Finalize(out);
            std::vector<unsigned char> hexvec(out, out+KEY_SIZE);
            std::string strHashFromPass = HexStr(hexvec);

            if (TimingResistantEqual(strHashFromPass, strHash)) {
                return true;
            }
        }
    }
    return false;
}

static bool RPCAuthorized(const std::string& strAuth)
{
    if (strRPCUserColonPass.empty()) // Belt-and-suspenders measure if InitRPCAuthentication was not called
        return false;
    if (strAuth.substr(0, 6) != "Basic ")
        return false;
    std::string strUserPass64 = strAuth.substr(6);
    boost::trim(strUserPass64);
    std::string strUserPass = DecodeBase64(strUserPass64);
    
    //Check if authorized under single-user field
    if (TimingResistantEqual(strUserPass, strRPCUserColonPass)) {
        return true;
    }
    return multiUserAuthorized(strUserPass);
}

static bool HTTPReq_JSONRPC(HTTPRequest* req, const std::string &) // HTTP 请求处理函数
{
    // JSONRPC handles only POST // JSONRPC 仅处理 POST 类型 HTTP 请求
    if (req->GetRequestMethod() != HTTPRequest::POST) {
        req->WriteReply(HTTP_BAD_METHOD, "JSONRPC server handles only POST requests");
        return false;
    }
    // Check authorization // 检查授权
    std::pair<bool, std::string> authHeader = req->GetHeader("authorization");
    if (!authHeader.first) {
        req->WriteHeader("WWW-Authenticate", WWW_AUTH_HEADER_DATA);
        req->WriteReply(HTTP_UNAUTHORIZED);
        return false;
    }

    if (!RPCAuthorized(authHeader.second)) { // 获取授权信息进行验证
        LogPrintf("ThreadRPCServer incorrect password attempt from %s\n", req->GetPeer().ToString());

        /* Deter brute-forcing
           If this results in a DoS the user really
           shouldn't have their RPC port exposed. */
        MilliSleep(250); // 睡 250ms

        req->WriteHeader("WWW-Authenticate", WWW_AUTH_HEADER_DATA);
        req->WriteReply(HTTP_UNAUTHORIZED);
        return false;
    }

    JSONRequest jreq; // JSON 请求对象
    try {
        // Parse request // 解析请求
        UniValue valRequest;
        if (!valRequest.read(req->ReadBody())) // 获取请求体
            throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");

        std::string strReply; // 响应内容
        // singleton request // 单例请求
        if (valRequest.isObject()) { // 请求体是一个对象
            jreq.parse(valRequest); // 解析请求

            UniValue result = tableRPC.execute(jreq.strMethod, jreq.params); // 执行相应方法及其参数

            // Send reply // 发送响应
            strReply = JSONRPCReply(result, NullUniValue, jreq.id); // 包装为 JSONRPC 响应内容

        // array of requests // 请求数组
        } else if (valRequest.isArray()) // 数组
            strReply = JSONRPCExecBatch(valRequest.get_array()); // 获取请求内容
        else
            throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");

        req->WriteHeader("Content-Type", "application/json"); // 写入响应头
        req->WriteReply(HTTP_OK, strReply); // 写入状态码和响应体
    } catch (const UniValue& objError) {
        JSONErrorReply(req, objError, jreq.id);
        return false;
    } catch (const std::exception& e) {
        JSONErrorReply(req, JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
        return false;
    }
    return true;
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
    if (!InitRPCAuthentication()) // 初始化 RPC 身份验证（rpc "用户名:密码"）
        return false;

    RegisterHTTPHandler("/", true, HTTPReq_JSONRPC); // 注册 http url 处理函数

    assert(EventBase()); // 返回 eventBase 指针对象
    httpRPCTimerInterface = new HTTPRPCTimerInterface(EventBase()); // 创建 http 定时器接口对象
    RPCRegisterTimerInterface(httpRPCTimerInterface); // RPC 注册定时器接口
    return true;
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
