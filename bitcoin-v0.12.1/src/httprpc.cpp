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

class HTTPRPCTimerInterface : public RPCTimerInterface // HTTPRPC ��ʱ���ӿ���
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
        return new HTTPRPCTimer(base, func, millis); // ��ָ��ʱ���ִ�� func һ��
    }
private:
    struct event_base* base;
};


/* Pre-base64-encoded authentication token */
static std::string strRPCUserColonPass; // base64 Ԥ����������֤����
/* Stored RPC timer interface (for unregistration) */ // �洢�� RPC ��ʱ���ӿڣ����ڽ�ע�ᣩ
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
//entries from config file. // �ú������������ļ��� -rpcauth ѡ��������û���������
static bool multiUserAuthorized(std::string strUserPass)
{    
    if (strUserPass.find(":") == std::string::npos) { // ��δ�ҵ�ð��
        return false; // ���� false����ʾ��֤ʧ��
    } // ���ҵ�
    std::string strUser = strUserPass.substr(0, strUserPass.find(":")); // ��ȡ�û���
    std::string strPass = strUserPass.substr(strUserPass.find(":") + 1); // ��ȡ����

    if (mapMultiArgs.count("-rpcauth") > 0) { // �� -rpcauth ѡ��ָ����ֵ
        //Search for multi-user login/pass "rpcauth" from config // �������ļ����������û���½/����ġ���֤��Ϣ��
        BOOST_FOREACH(std::string strRPCAuth, mapMultiArgs["-rpcauth"]) // ���� -rpcauth ѡ���Ӧ��ֵ
        { // -rpcauth ��ʽ��<USERNAME>:<SALT>$<HASH>
            std::vector<std::string> vFields; // ���� 3 ����
            boost::split(vFields, strRPCAuth, boost::is_any_of(":$")); // ���� ":$" �ָ����֤��Ϣ
            if (vFields.size() != 3) {
                //Incorrect formatting in config file // �����ļ��ĸ�ʽ����ȷ
                continue; // ����
            }

            std::string strName = vFields[0]; // ��ȡ�û���
            if (!TimingResistantEqual(strName, strUser)) { // �Ա���֤�û���
                continue;
            }

            std::string strSalt = vFields[1]; // ��ȡ��ֵ
            std::string strHash = vFields[2]; // ��ȡ��ϣֵ

            unsigned int KEY_SIZE = 32;
            unsigned char *out = new unsigned char[KEY_SIZE]; // ���� 256 λ�ĶѶ���
            
            CHMAC_SHA256(reinterpret_cast<const unsigned char*>(strSalt.c_str()), strSalt.size()).Write(reinterpret_cast<const unsigned char*>(strPass.c_str()), strPass.size()).Finalize(out); // DSHA256
            std::vector<unsigned char> hexvec(out, out+KEY_SIZE); // ��ʼ�� 256 Ϊ������
            std::string strHashFromPass = HexStr(hexvec); // ת��Ϊ 16 �����ַ���

            if (TimingResistantEqual(strHashFromPass, strHash)) { // �Աȹ�ϣֵ
                return true; // ��֤�ɹ������� true
            }
        }
    } // ��֤ʧ��
    return false; // ���� false
}

static bool RPCAuthorized(const std::string& strAuth)
{
    if (strRPCUserColonPass.empty()) // Belt-and-suspenders measure if InitRPCAuthentication was not called
        return false; // ��δ���� InitRPCAuthentication ��ʼ�� strRPCUserColonPass����ֱ�ӷ��� false ��ʾ��֤ʧ��
    if (strAuth.substr(0, 6) != "Basic ") // ����֤��Ϣǰ 6 ���ַ��� "Basic "
        return false; // ֱ�ӷ��� false ��ʾ��֤ʧ��
    std::string strUserPass64 = strAuth.substr(6); // ��ȡ���±�Ϊ 6 ���ַ���ʼ���ִ�
    boost::trim(strUserPass64); // ȥ��ԭ�ַ���ͷβ�Ŀո�
    std::string strUserPass = DecodeBase64(strUserPass64); // base64 ����
    
    //Check if authorized under single-user field // ����Ƿ��ڵ��û��ֶ�����Ȩ
    if (TimingResistantEqual(strUserPass, strRPCUserColonPass)) {
        return true; // ��֤�ɹ����� true
    } // ����
    return multiUserAuthorized(strUserPass); // ���ж��û���Ȩ���
}

static bool HTTPReq_JSONRPC(HTTPRequest* req, const std::string &) // HTTP ��������
{
    // JSONRPC handles only POST // 1.JSONRPC ������ POST ���� HTTP ����
    if (req->GetRequestMethod() != HTTPRequest::POST) { // ���� POST ���͵�����
        req->WriteReply(HTTP_BAD_METHOD, "JSONRPC server handles only POST requests"); // ������Ϣ
        return false; // ֱ���˳������� false
    }
    // Check authorization // 2.�����Ȩ
    std::pair<bool, std::string> authHeader = req->GetHeader("authorization"); // ��ȡͷ����Ȩ�ֶ�
    if (!authHeader.first) { // ��������
        req->WriteHeader("WWW-Authenticate", WWW_AUTH_HEADER_DATA);
        req->WriteReply(HTTP_UNAUTHORIZED);
        return false; // �˳������� false
    }

    if (!RPCAuthorized(authHeader.second)) { // �Ի�ȡ��Ȩ��Ϣ������֤
        LogPrintf("ThreadRPCServer incorrect password attempt from %s\n", req->GetPeer().ToString());

        /* Deter brute-forcing // ��ֹ����
           If this results in a DoS the user really // ����⵼�� DoS���û�ʵ���ϲ�Ӧ�ñ�¶��˿ڡ�
           shouldn't have their RPC port exposed. */
        MilliSleep(250); // ˯ 250ms

        req->WriteHeader("WWW-Authenticate", WWW_AUTH_HEADER_DATA);
        req->WriteReply(HTTP_UNAUTHORIZED);
        return false;
    }

    JSONRequest jreq; // JSON �������
    try {
        // Parse request // 3.��������
        UniValue valRequest; // ����һ�� JSON ����
        if (!valRequest.read(req->ReadBody())) // ��ȡ������
            throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");

        std::string strReply; // 4.��Ӧ�����ַ���
        // singleton request // 4.1.��������
        if (valRequest.isObject()) { // ��������һ������
            jreq.parse(valRequest); // �������󣬷��� JSON ���������

            UniValue result = tableRPC.execute(jreq.strMethod, jreq.params); // ������Ӧ�Ĳ���ִ�з�������ȡ��Ӧ���

            // Send reply // ������Ӧ
            strReply = JSONRPCReply(result, NullUniValue, jreq.id); // ��װΪ JSONRPC ��Ӧ�����ַ���

        // array of requests // ��������
        } else if (valRequest.isArray()) // 4.2.����
            strReply = JSONRPCExecBatch(valRequest.get_array()); // ����������ȡ�������Ӧ�����ַ���
        else
            throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");

        req->WriteHeader("Content-Type", "application/json"); // 5.д����Ӧͷ
        req->WriteReply(HTTP_OK, strReply); // д��״̬�����Ӧ�����ַ���
    } catch (const UniValue& objError) {
        JSONErrorReply(req, objError, jreq.id);
        return false;
    } catch (const std::exception& e) {
        JSONErrorReply(req, JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
        return false;
    }
    return true; // 6.�ɹ����� true
}

static bool InitRPCAuthentication()
{
    if (mapArgs["-rpcpassword"] == "")
    { // ����Ϊ��
        LogPrintf("No rpcpassword set - using random cookie authentication\n");
        if (!GenerateAuthCookie(&strRPCUserColonPass)) { // ���� cookie �ַ���
            uiInterface.ThreadSafeMessageBox(
                _("Error: A fatal internal error occurred, see debug.log for details"), // Same message as AbortNode
                "", CClientUIInterface::MSG_ERROR);
            return false;
        }
    } else { // ����ǿ�
        LogPrintf("Config options rpcuser and rpcpassword will soon be deprecated. Locally-run instances may remove rpcuser to use cookie-based auth, or may be replaced with rpcauth. Please see share/rpcuser for rpcauth auth generation.\n");
        strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"]; // ƴ�� RPC "user:pass" �ַ���
    }
    return true;
}

bool StartHTTPRPC()
{
    LogPrint("rpc", "Starting HTTP RPC server\n");
    if (!InitRPCAuthentication()) // 1.��ʼ�� RPC �����֤��rpc "�û���:����"��
        return false;

    RegisterHTTPHandler("/", true, HTTPReq_JSONRPC); // 2.ע�� http url ������

    assert(EventBase()); // ���� event_base ����ָ��
    httpRPCTimerInterface = new HTTPRPCTimerInterface(EventBase()); // 3.���� http ��ʱ���ӿڶ���
    RPCRegisterTimerInterface(httpRPCTimerInterface); // ��ע�� RPC ��ʱ���ӿ�
    return true; // �ɹ����� true
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
