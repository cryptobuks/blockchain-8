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

static bool AppInitRPC(int argc, char* argv[]) // 2.0.Ӧ�ó����ʼ��Զ�̹��̵���
{
    //
    // Parameters
    //
    ParseParameters(argc, argv); // 2.1.��������
    if (argc<2 || mapArgs.count("-?") || mapArgs.count("-h") || mapArgs.count("-help") || mapArgs.count("-version")) { // 2.2.�����Ͱ汾��Ϣ
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
    if (!boost::filesystem::is_directory(GetDataDir(false))) { // 2.3.�������Ŀ¼
        fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
        return false;
    }
    try {
        ReadConfigFile(mapArgs, mapMultiArgs); // 2.4.�������ļ�
    } catch (const std::exception& e) {
        fprintf(stderr,"Error reading configuration file: %s\n", e.what());
        return false;
    }
    // Check for -testnet or -regtest parameter (BaseParams() calls are only valid after this clause)
    try {
        SelectBaseParams(ChainNameFromCommandLine()); // 2.5.��������ѡ��������������RPC �˿ڡ�����Ŀ¼����
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
struct HTTPReply // ���� request_done ������Ӧ�ṹ
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
        const char *data = (const char*)evbuffer_pullup(buf, size); // ��ȡ��Ӧ������
        if (data)
            reply->body = std::string(data, size); // ���� HTTP ��Ӧ��
        evbuffer_drain(buf, size); // ���ĺ���������Ѷ�����
    }
}

UniValue CallRPC(const string& strMethod, const UniValue& params)
{
    std::string host = GetArg("-rpcconnect", DEFAULT_RPCCONNECT); // Զ�̹��̵��� IP ��ַ��Ĭ�ϱ������� IP
    int port = GetArg("-rpcport", BaseParams().RPCPort()); // Զ�̹��̵��ö˿ڣ�Ĭ�ϻ��������е� RPC �˿�

    // Create event base // �����¼������
    struct event_base *base = event_base_new(); // TODO RAII
    if (!base)
        throw runtime_error("cannot create event_base");

    // Synchronously look up hostname // ͬ������������
    struct evhttp_connection *evcon = evhttp_connection_base_new(base, NULL, host.c_str(), port); // TODO RAII
    if (evcon == NULL)
        throw runtime_error("create connection failed");
    evhttp_connection_set_timeout(evcon, GetArg("-rpcclienttimeout", DEFAULT_HTTP_CLIENT_TIMEOUT)); // Զ�̹��̵��ÿͻ������ӳ�ʱ��Ĭ�� 900 s

    HTTPReply response; // HTTP ��Ӧ������״̬�����ݣ�
    struct evhttp_request *req = evhttp_request_new(http_request_done, (void*)&response); // TODO RAII // �½�һ���������ͷ + ������
    if (req == NULL)
        throw runtime_error("create http request failed");

    // Get credentials // ��ȡƾ֤
    std::string strRPCUserColonPass; // ���ڱ����û���������
    if (mapArgs["-rpcpassword"] == "") { // δ�ṩ����
        // Try fall back to cookie-based authentication if no password is provided
        if (!GetAuthCookie(&strRPCUserColonPass)) { // ��ȡ cookie��"cookie ��Ȩ�û���:password"
            throw runtime_error(strprintf(
                _("Could not locate RPC credentials. No authentication cookie could be found, and no rpcpassword is set in the configuration file (%s)"),
                    GetConfigFile().string().c_str()));

        }
    } else {
        strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"]; // username:password
    }

    struct evkeyvalq *output_headers = evhttp_request_get_output_headers(req); // ��ȡ�����������ͷ
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str()); // ������������
    evhttp_add_header(output_headers, "Connection", "close"); // �رճ����ӣ���������������ӾͶϵ���
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str()); // �����Ȩ���û��� + ���룩

    // Attach request data // ��ȡ��������
    std::string strRequest = JSONRPCRequest(strMethod, params, 1); // RPC �������ʹ�� Json ��װ
    struct evbuffer * output_buffer = evhttp_request_get_output_buffer(req); // ��ȡ������������
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size()); // �������Ĳ������������

    int r = evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/"); // ���� POST ����
    if (r != 0) { // ���ͳɹ�������ֵΪ 0
        evhttp_connection_free(evcon);
        event_base_free(base);
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base); // �¼�����ѭ���������� event_base_loop��ѭ���ȴ��¼���֪ͨ�¼�����
    evhttp_connection_free(evcon); // �ͷ� HTTP ����
    event_base_free(base); // �ͷ����¼������ event_base �����������ڴ�

    if (response.status == 0) // ��Ӧ״̬��Ϊ 0����ʾ�޷����ӵ�������
        throw CConnectionFailed("couldn't connect to server");
    else if (response.status == HTTP_UNAUTHORIZED) // 401 ��ʾδ��Ȩ���� RPC �û��������벻��ȷ
        throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR) // ���ڵ��� 400 ��ʾ���������ش���
        throw runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty()) // ��Ӧ��Ϊ�գ��׳��쳣
        throw runtime_error("no response from server");

    // Parse reply // ������Ӧ
    UniValue valReply(UniValue::VSTR); // �����ַ���������Ӧ����
    if (!valReply.read(response.body)) // ������Ӧ������ pending
        throw runtime_error("couldn't parse reply from server");
    const UniValue& reply = valReply.get_obj(); // pending
    if (reply.empty())
        throw runtime_error("expected reply to have result, error and id properties");

    return reply;
}

int CommandLineRPC(int argc, char *argv[]) // 3.0.������Զ�̹��̵���
{
    string strPrint;
    int nRet = 0;
    try {
        // Skip switches
        while (argc > 1 && IsSwitchChar(argv[1][0])) { // �������� '-' �� '/' ǰ׺�Ĳ���
            argc--;
            argv++;
        }

        // Method
        if (argc < 2) // û�м������в���
            throw runtime_error("too few parameters"); // �׳��쳣
        string strMethod = argv[1]; // ������

        // Parameters default to strings
        std::vector<std::string> strParams(&argv[2], &argv[argc]); // ������Ӧ�Ĳ�������һ�������һ����
        UniValue params = RPCConvertValues(strMethod, strParams); // �������

        // Execute and handle connection failures with -rpcwait
        const bool fWait = GetBoolArg("-rpcwait", false); // Զ�̹��̵��õȴ�������ʧ�ܺ�ѭ���ٴε��ã���Ĭ�Ϲر�
        do {
            try {
                const UniValue reply = CallRPC(strMethod, params); // ���� RPC��HTTP ���󣩣�����ȡ��Ӧ

                // Parse reply
                const UniValue& result = find_value(reply, "result"); // ������Ӧ���
                const UniValue& error  = find_value(reply, "error"); // ������Ӧ������Ϣ

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
                    if (result.isNull()) // ���Ϊ��
                        strPrint = "";
                    else if (result.isStr()) // ������ַ�������
                        strPrint = result.get_str(); // ��ȡ�ַ������͵Ľ��
                    else // �ǿ� �� ���ַ������͵Ľ��
                        strPrint = result.write(2); // ��ʽ������
                }
                // Connection succeeded, no need to retry.
                break; // ���ӣ�������Ӧ���ɹ�������Ҫ����
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

    if (strPrint != "") { // ��Ӧ�ַ����ǿ�
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str()); // �����Ӧ�������Ļ����׼��� �� ��׼����
    }
    return nRet;
}

int main(int argc, char* argv[]) // 0.��ȡ��Զ�̹��̵��ã������в���
{
    SetupEnvironment(); // 1.�������л�����ͬ bitcoind��
    if (!SetupNetworking()) { // ���� windows socket
        fprintf(stderr, "Error: Initializing networking failed\n");
        exit(1);
    }

    try {
        if(!AppInitRPC(argc, argv)) // 2.Ӧ�ó����ʼ��Զ�̹��̵��ã�����������������Ŀ¼�������ļ���RPC �˿ڣ�
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
        ret = CommandLineRPC(argc, argv); // 3.������Զ�̹��̵���
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "CommandLineRPC()");
    } catch (...) {
        PrintExceptionContinue(NULL, "CommandLineRPC()");
    }
    return ret;
}
