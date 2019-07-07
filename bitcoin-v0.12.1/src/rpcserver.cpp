// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcserver.h"

#include "base58.h"
#include "init.h"
#include "random.h"
#include "sync.h"
#include "ui_interface.h"
#include "util.h"
#include "utilstrencodings.h"

#include <univalue.h>

#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_upper()

using namespace RPCServer;
using namespace std;

static bool fRPCRunning = false; // RPC ����״̬��Ĭ��Ϊ false
static bool fRPCInWarmup = true;
static std::string rpcWarmupStatus("RPC server started"); // ȫ�־�̬ rpc Ԥ��״̬�ַ���
static CCriticalSection cs_rpcWarmup; // rpc Ԥ��״̬��
/* Timer-creating functions */ // ��ʱ����������
static std::vector<RPCTimerInterface*> timerInterfaces; // RPC ��ʱ���ӿ��б�
/* Map of name to timer.
 * @note Can be changed to std::unique_ptr when C++11 */ // ��ʱ������ӳ��
static std::map<std::string, boost::shared_ptr<RPCTimerBase> > deadlineTimers; // ��ֹʱ�䶨ʱ��

static struct CRPCSignals // RPC �ź�
{
    boost::signals2::signal<void ()> Started;
    boost::signals2::signal<void ()> Stopped;
    boost::signals2::signal<void (const CRPCCommand&)> PreCommand;
    boost::signals2::signal<void (const CRPCCommand&)> PostCommand;
} g_rpcSignals; // rpc �ź�ȫ�ֶ���

void RPCServer::OnStarted(boost::function<void ()> slot)
{
    g_rpcSignals.Started.connect(slot);
}

void RPCServer::OnStopped(boost::function<void ()> slot)
{
    g_rpcSignals.Stopped.connect(slot);
}

void RPCServer::OnPreCommand(boost::function<void (const CRPCCommand&)> slot)
{
    g_rpcSignals.PreCommand.connect(boost::bind(slot, _1));
}

void RPCServer::OnPostCommand(boost::function<void (const CRPCCommand&)> slot)
{
    g_rpcSignals.PostCommand.connect(boost::bind(slot, _1));
}

void RPCTypeCheck(const UniValue& params,
                  const list<UniValue::VType>& typesExpected,
                  bool fAllowNull)
{
    unsigned int i = 0;
    BOOST_FOREACH(UniValue::VType t, typesExpected)
    {
        if (params.size() <= i)
            break;

        const UniValue& v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.isNull()))))
        {
            string err = strprintf("Expected type %s, got %s",
                                   uvTypeName(t), uvTypeName(v.type()));
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
        i++;
    }
}

void RPCTypeCheckObj(const UniValue& o,
                  const map<string, UniValue::VType>& typesExpected,
                  bool fAllowNull)
{
    BOOST_FOREACH(const PAIRTYPE(string, UniValue::VType)& t, typesExpected)
    {
        const UniValue& v = find_value(o, t.first);
        if (!fAllowNull && v.isNull())
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing %s", t.first));

        if (!((v.type() == t.second) || (fAllowNull && (v.isNull()))))
        {
            string err = strprintf("Expected type %s for %s, got %s",
                                   uvTypeName(t.second), t.first, uvTypeName(v.type()));
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }
}

CAmount AmountFromValue(const UniValue& value)
{
    if (!value.isNum() && !value.isStr()) // ��ֵ����Ϊ���ֻ��ַ�������
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
    CAmount amount; // int64_t
    if (!ParseFixedPoint(value.getValStr(), 8, &amount)) // ��������ʼ�����
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    if (!MoneyRange(amount)) // ����Χ
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
    return amount; // ���ظý��
}

UniValue ValueFromAmount(const CAmount& amount)
{
    bool sign = amount < 0;
    int64_t n_abs = (sign ? -amount : amount);
    int64_t quotient = n_abs / COIN;
    int64_t remainder = n_abs % COIN;
    return UniValue(UniValue::VNUM,
            strprintf("%s%d.%08d", sign ? "-" : "", quotient, remainder));
}

uint256 ParseHashV(const UniValue& v, string strName)
{
    string strHex;
    if (v.isStr())
        strHex = v.get_str();
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    uint256 result;
    result.SetHex(strHex);
    return result;
}
uint256 ParseHashO(const UniValue& o, string strKey)
{
    return ParseHashV(find_value(o, strKey), strKey);
}
vector<unsigned char> ParseHexV(const UniValue& v, string strName)
{
    string strHex;
    if (v.isStr())
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    return ParseHex(strHex);
}
vector<unsigned char> ParseHexO(const UniValue& o, string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}

/**
 * Note: This interface may still be subject to change.
 */
// �ýӿڿ��ܻ�ı�
std::string CRPCTable::help(const std::string& strCommand) const
{
    string strRet; // �������յķ��ؽ��
    string category; // ���
    set<rpcfn_type> setDone; // ������Ӧ�Ļص�����
    vector<pair<string, const CRPCCommand*> > vCommands; // �����б�

    for (map<string, const CRPCCommand*>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end(); ++mi)
        vCommands.push_back(make_pair(mi->second->category + mi->first, mi->second)); // <category+name, const CRPCCommand*>
    sort(vCommands.begin(), vCommands.end()); // �� key ��������

    BOOST_FOREACH(const PAIRTYPE(string, const CRPCCommand*)& command, vCommands)
    { // �����б��е�����
        const CRPCCommand *pcmd = command.second; // ȡ�� RPC ����ָ��
        string strMethod = pcmd->name; // ��÷�����
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != string::npos) // �������к��� "label"
            continue; // ������
        if ((strCommand != "" || pcmd->category == "hidden") && strMethod != strCommand) // ָ��������ǿ� �� ���Ϊ "hidden" �� ������������ָ��������
            continue; // ������
        try
        {
            UniValue params;
            rpcfn_type pfn = pcmd->actor; // ע���Ӧ�ص�����
            if (setDone.insert(pfn).second) // ��ִ���б����ص��ɹ�
                (*pfn)(params, true); // ���������ִ�иûص���ͬʱ��� fHelp Ϊ true
        }
        catch (const std::exception& e)
        {
            // Help text is returned in an exception
            string strHelp = string(e.what()); // �õ��ص������׳����쳣����������Ϣ
            if (strCommand == "") // ���ָ������Ϊ�ռ�δָ������
            {
                if (strHelp.find('\n') != string::npos) // ��������Ϣ�д��� '\n'
                    strHelp = strHelp.substr(0, strHelp.find('\n')); // ��ȡ��һ�� '\n' ֮ǰ�ĵ��ַ�������������

                if (category != pcmd->category) // ���ͬ��category ��ʼ��Ϊ��
                {
                    if (!category.empty()) // category �ǿ�
                        strRet += "\n"; // ���뻻�У���ʼ���Ϊ�գ�
                    category = pcmd->category; // �õ����
                    string firstLetter = category.substr(0,1); // ��ȡ�������ĸ
                    boost::to_upper(firstLetter); // ת��Ϊ��д��ĸ
                    strRet += "== " + firstLetter + category.substr(1) + " ==\n"; // ƴ������ĸ��д����𵽷��صĽ��
                }
            }
            strRet += strHelp + "\n"; // ƴ�� RPC ������
        }
    } // �ظ����Ϲ��̣�ֱ��������ÿһ��ע��� RPC ����
    if (strRet == "") // ����ֵΪ�ձ�ʾָ����δ֪����
        strRet = strprintf("help: unknown command: %s\n", strCommand); // ƴ�Ӵ�����Ϣ
    strRet = strRet.substr(0,strRet.size()-1); // ȥ����β�� '\n'
    return strRet; // ���ؽ��
}

UniValue help(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1) // 1.�������Ϊ 1 ����RPC ���
        throw runtime_error( // �����������
            "help ( \"command\" )\n"
            "\nList all commands, or get help for a specified command.\n"
            "\nArguments:\n"
            "1. \"command\"     (string, optional) The command to get help on\n"
            "\nResult:\n"
            "\"text\"     (string) The help text\n"
        );

    string strCommand;
    if (params.size() > 0) // 2.�����в���
        strCommand = params[0].get_str(); // ��ȡ����������ַ���

    return tableRPC.help(strCommand); // 3.�����������Ϊ�գ�������
}


UniValue stop(const UniValue& params, bool fHelp)
{
    // Accept the deprecated and ignored 'detach' boolean argument
    if (fHelp || params.size() > 1) // 1.�������Ϊ 1 ���������Ѿ���ʱ�����޲���
        throw runtime_error(
            "stop\n"
            "\nStop Bitcoin server.");
    // Event loop will exit after current HTTP requests have been handled, so
    // this reply will get back to the client. // �ڵ�ǰ HTTP ���󱻴����ʱ��ѭ���Ż��˳�
    StartShutdown(); // 2.�رձ��رҺ��ķ���
    return "Bitcoin server stopping"; // 3.����ֹͣ��Ϣ
}

/**
 * Call Table
 */ // �����б�
static const CRPCCommand vRPCCommands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    /* Overall control/query calls */
    { "control",            "getinfo",                &getinfo,                true  }, /* uses wallet if enabled */
    { "control",            "help",                   &help,                   true  },
    { "control",            "stop",                   &stop,                   true  },

    /* P2P networking */
    { "network",            "getnetworkinfo",         &getnetworkinfo,         true  },
    { "network",            "addnode",                &addnode,                true  },
    { "network",            "disconnectnode",         &disconnectnode,         true  },
    { "network",            "getaddednodeinfo",       &getaddednodeinfo,       true  },
    { "network",            "getconnectioncount",     &getconnectioncount,     true  },
    { "network",            "getnettotals",           &getnettotals,           true  },
    { "network",            "getpeerinfo",            &getpeerinfo,            true  },
    { "network",            "ping",                   &ping,                   true  },
    { "network",            "setban",                 &setban,                 true  },
    { "network",            "listbanned",             &listbanned,             true  },
    { "network",            "clearbanned",            &clearbanned,            true  },

    /* Block chain and UTXO */
    { "blockchain",         "getblockchaininfo",      &getblockchaininfo,      true  },
    { "blockchain",         "getbestblockhash",       &getbestblockhash,       true  },
    { "blockchain",         "getblockcount",          &getblockcount,          true  },
    { "blockchain",         "getblock",               &getblock,               true  },
    { "blockchain",         "getblockhash",           &getblockhash,           true  },
    { "blockchain",         "getblockheader",         &getblockheader,         true  },
    { "blockchain",         "getchaintips",           &getchaintips,           true  },
    { "blockchain",         "getdifficulty",          &getdifficulty,          true  },
    { "blockchain",         "getmempoolinfo",         &getmempoolinfo,         true  },
    { "blockchain",         "getrawmempool",          &getrawmempool,          true  },
    { "blockchain",         "gettxout",               &gettxout,               true  },
    { "blockchain",         "gettxoutproof",          &gettxoutproof,          true  },
    { "blockchain",         "verifytxoutproof",       &verifytxoutproof,       true  },
    { "blockchain",         "gettxoutsetinfo",        &gettxoutsetinfo,        true  },
    { "blockchain",         "verifychain",            &verifychain,            true  },

    /* Mining */
    { "mining",             "getblocktemplate",       &getblocktemplate,       true  },
    { "mining",             "getmininginfo",          &getmininginfo,          true  },
    { "mining",             "getnetworkhashps",       &getnetworkhashps,       true  },
    { "mining",             "prioritisetransaction",  &prioritisetransaction,  true  },
    { "mining",             "submitblock",            &submitblock,            true  },

    /* Coin generation */
    { "generating",         "getgenerate",            &getgenerate,            true  },
    { "generating",         "setgenerate",            &setgenerate,            true  },
    { "generating",         "generate",               &generate,               true  },

    /* Raw transactions */
    { "rawtransactions",    "createrawtransaction",   &createrawtransaction,   true  },
    { "rawtransactions",    "decoderawtransaction",   &decoderawtransaction,   true  },
    { "rawtransactions",    "decodescript",           &decodescript,           true  },
    { "rawtransactions",    "getrawtransaction",      &getrawtransaction,      true  },
    { "rawtransactions",    "sendrawtransaction",     &sendrawtransaction,     false },
    { "rawtransactions",    "signrawtransaction",     &signrawtransaction,     false }, /* uses wallet if enabled */
#ifdef ENABLE_WALLET
    { "rawtransactions",    "fundrawtransaction",     &fundrawtransaction,     false },
#endif

    /* Utility functions */
    { "util",               "createmultisig",         &createmultisig,         true  },
    { "util",               "validateaddress",        &validateaddress,        true  }, /* uses wallet if enabled */
    { "util",               "verifymessage",          &verifymessage,          true  },
    { "util",               "estimatefee",            &estimatefee,            true  },
    { "util",               "estimatepriority",       &estimatepriority,       true  },
    { "util",               "estimatesmartfee",       &estimatesmartfee,       true  },
    { "util",               "estimatesmartpriority",  &estimatesmartpriority,  true  },

    /* Not shown in help */
    { "hidden",             "invalidateblock",        &invalidateblock,        true  },
    { "hidden",             "reconsiderblock",        &reconsiderblock,        true  },
    { "hidden",             "setmocktime",            &setmocktime,            true  },
#ifdef ENABLE_WALLET
    { "hidden",             "resendwallettransactions", &resendwallettransactions, true},
#endif

#ifdef ENABLE_WALLET
    /* Wallet */
    { "wallet",             "addmultisigaddress",     &addmultisigaddress,     true  },
    { "wallet",             "backupwallet",           &backupwallet,           true  },
    { "wallet",             "dumpprivkey",            &dumpprivkey,            true  },
    { "wallet",             "dumpwallet",             &dumpwallet,             true  },
    { "wallet",             "encryptwallet",          &encryptwallet,          true  },
    { "wallet",             "getaccountaddress",      &getaccountaddress,      true  },
    { "wallet",             "getaccount",             &getaccount,             true  },
    { "wallet",             "getaddressesbyaccount",  &getaddressesbyaccount,  true  },
    { "wallet",             "getbalance",             &getbalance,             false },
    { "wallet",             "getnewaddress",          &getnewaddress,          true  },
    { "wallet",             "getrawchangeaddress",    &getrawchangeaddress,    true  },
    { "wallet",             "getreceivedbyaccount",   &getreceivedbyaccount,   false },
    { "wallet",             "getreceivedbyaddress",   &getreceivedbyaddress,   false },
    { "wallet",             "gettransaction",         &gettransaction,         false },
    { "wallet",             "abandontransaction",     &abandontransaction,     false },
    { "wallet",             "getunconfirmedbalance",  &getunconfirmedbalance,  false },
    { "wallet",             "getwalletinfo",          &getwalletinfo,          false },
    { "wallet",             "importprivkey",          &importprivkey,          true  },
    { "wallet",             "importwallet",           &importwallet,           true  },
    { "wallet",             "importaddress",          &importaddress,          true  },
    { "wallet",             "importpubkey",           &importpubkey,           true  },
    { "wallet",             "keypoolrefill",          &keypoolrefill,          true  },
    { "wallet",             "listaccounts",           &listaccounts,           false },
    { "wallet",             "listaddressgroupings",   &listaddressgroupings,   false },
    { "wallet",             "listlockunspent",        &listlockunspent,        false },
    { "wallet",             "listreceivedbyaccount",  &listreceivedbyaccount,  false },
    { "wallet",             "listreceivedbyaddress",  &listreceivedbyaddress,  false },
    { "wallet",             "listsinceblock",         &listsinceblock,         false },
    { "wallet",             "listtransactions",       &listtransactions,       false },
    { "wallet",             "listunspent",            &listunspent,            false },
    { "wallet",             "lockunspent",            &lockunspent,            true  },
    { "wallet",             "move",                   &movecmd,                false },
    { "wallet",             "sendfrom",               &sendfrom,               false },
    { "wallet",             "sendmany",               &sendmany,               false },
    { "wallet",             "sendtoaddress",          &sendtoaddress,          false },
    { "wallet",             "setaccount",             &setaccount,             true  },
    { "wallet",             "settxfee",               &settxfee,               true  },
    { "wallet",             "signmessage",            &signmessage,            true  },
    { "wallet",             "walletlock",             &walletlock,             true  },
    { "wallet",             "walletpassphrasechange", &walletpassphrasechange, true  },
    { "wallet",             "walletpassphrase",       &walletpassphrase,       true  },
#endif // ENABLE_WALLET
};

CRPCTable::CRPCTable() // �ڸ��ļ�ĩβ����ȫ�ֳ������󣬵��øú������� RPC ����ע��
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++)
    { // �������涨��� RPC �����б�
        const CRPCCommand *pcmd; // RPC ����ָ��

        pcmd = &vRPCCommands[vcidx]; // ָ��һ�� RPC ����
        mapCommands[pcmd->name] = pcmd; // �Ѹ�����ע�ᵽ RPC �����б���
    }
}

const CRPCCommand *CRPCTable::operator[](const std::string &name) const // ���ص��±������
{
    map<string, const CRPCCommand*>::const_iterator it = mapCommands.find(name); // ͨ��������������Ӧ����
    if (it == mapCommands.end()) // ��δ�ҵ�
        return NULL; // ���ؿ�
    return (*it).second; // �ҵ�������Ӧ����
}

bool StartRPC()
{
    LogPrint("rpc", "Starting RPC\n");
    fRPCRunning = true; // ���� RPC ����״̬Ϊ true
    g_rpcSignals.Started(); // �˰汾δ�ҵ��ź�ע�� pending
    return true; // �ɹ����� true
}

void InterruptRPC()
{
    LogPrint("rpc", "Interrupting RPC\n");
    // Interrupt e.g. running longpolls
    fRPCRunning = false;
}

void StopRPC()
{
    LogPrint("rpc", "Stopping RPC\n");
    deadlineTimers.clear();
    g_rpcSignals.Stopped();
}

bool IsRPCRunning()
{
    return fRPCRunning; // ���� RPC ����״̬
}

void SetRPCWarmupStatus(const std::string& newStatus)
{
    LOCK(cs_rpcWarmup); // rpc Ԥ��״̬����
    rpcWarmupStatus = newStatus; // ������״̬
}

void SetRPCWarmupFinished()
{
    LOCK(cs_rpcWarmup);
    assert(fRPCInWarmup);
    fRPCInWarmup = false;
}

bool RPCIsInWarmup(std::string *outStatus)
{
    LOCK(cs_rpcWarmup);
    if (outStatus)
        *outStatus = rpcWarmupStatus;
    return fRPCInWarmup;
}

void JSONRequest::parse(const UniValue& valRequest)
{
    // Parse request // ��������
    if (!valRequest.isObject()) // ��������� JSON ����
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object"); // �׳��쳣����Ч�������
    const UniValue& request = valRequest.get_obj(); // ��ȡ JSON �������

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id"); // ���ڽ��� id�����������Դ˴��Ĵ����� id

    // Parse method // ��������
    UniValue valMethod = find_value(request, "method"); // ��ȡ����
    if (valMethod.isNull()) // �����ǿ�
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (!valMethod.isStr()) // ��������Ϊ�ַ���
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str(); // ��ȡ����
    if (strMethod != "getblocktemplate") // �������� "getblocktemplate"
        LogPrint("rpc", "ThreadRPCServer method=%s\n", SanitizeString(strMethod));

    // Parse params // ��������
    UniValue valParams = find_value(request, "params"); // ��ȡ����Ĳ���
    if (valParams.isArray()) // ������Ϊ json ����
        params = valParams.get_array(); // ��ȡ������
    else if (valParams.isNull()) // ������Ϊ��
        params = UniValue(UniValue::VARR); // �½��������Ϳն���
    else // ���򣨷����Ĳ�������Ϊ json �������ͣ�
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array"); // �׳�����
}

static UniValue JSONRPCExecOne(const UniValue& req)
{
    UniValue rpc_result(UniValue::VOBJ); // �����������͵� JSON ����

    JSONRequest jreq;
    try {
        jreq.parse(req); // ��������

        UniValue result = tableRPC.execute(jreq.strMethod, jreq.params); // ת�� execute ���������ִ������
        rpc_result = JSONRPCReplyObj(result, NullUniValue, jreq.id); // ��װ���Ϊ JSON ����
    }
    catch (const UniValue& objError)
    {
        rpc_result = JSONRPCReplyObj(NullUniValue, objError, jreq.id);
    }
    catch (const std::exception& e)
    {
        rpc_result = JSONRPCReplyObj(NullUniValue,
                                     JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result; // ���� rpc �������
}

std::string JSONRPCExecBatch(const UniValue& vReq)
{
    UniValue ret(UniValue::VARR); // �����������͵� JSON ����
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++) // ��������
        ret.push_back(JSONRPCExecOne(vReq[reqIdx])); // ִ��һ�β�����Ӧ����׷�ӵ� JSON ������

    return ret.write() + "\n"; // �� JSON ����ת��Ϊ�ַ�����ƴ�ӻ��з��󷵻�
}

UniValue CRPCTable::execute(const std::string &strMethod, const UniValue &params) const
{
    // Return immediately if in warmup // 1.�������Ԥ��״̬�����̷���
    {
        LOCK(cs_rpcWarmup); // rpc Ԥ��״̬����
        if (fRPCInWarmup) // ������Ԥ��״̬
            throw JSONRPCError(RPC_IN_WARMUP, rpcWarmupStatus); // �׳��쳣
    }

    // Find method // 2.���ҷ���
    const CRPCCommand *pcmd = tableRPC[strMethod]; // ͨ����������ȡ��Ӧ RPC �����
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");

    g_rpcSignals.PreCommand(*pcmd); // 3.Ԥ����������������Ƿ�����ȫģʽ

    try
    {
        // Execute // 4.ִ��
        return pcmd->actor(params, false); // ��������ǣ�ִ����Ӧ�ĺ�����Ϊ
    }
    catch (const std::exception& e)
    {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }

    g_rpcSignals.PostCommand(*pcmd); // 5.����������ź�δע�ᴦ����
}

std::string HelpExampleCli(const std::string& methodname, const std::string& args)
{
    return "> bitcoin-cli " + methodname + " " + args + "\n";
}

std::string HelpExampleRpc(const std::string& methodname, const std::string& args)
{
    return "> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", "
        "\"method\": \"" + methodname + "\", \"params\": [" + args + "] }' -H 'content-type: text/plain;' http://127.0.0.1:8332/\n";
}

void RPCRegisterTimerInterface(RPCTimerInterface *iface)
{
    timerInterfaces.push_back(iface); // ���붨ʱ���ӿ��б�
}

void RPCUnregisterTimerInterface(RPCTimerInterface *iface)
{
    std::vector<RPCTimerInterface*>::iterator i = std::find(timerInterfaces.begin(), timerInterfaces.end(), iface);
    assert(i != timerInterfaces.end());
    timerInterfaces.erase(i);
}

void RPCRunLater(const std::string& name, boost::function<void(void)> func, int64_t nSeconds)
{
    if (timerInterfaces.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No timer handler registered for RPC");
    deadlineTimers.erase(name); // ����ָ�����ֵĶ�ʱ��
    RPCTimerInterface* timerInterface = timerInterfaces.back(); // �õ��б������һ����ʱ��
    LogPrint("rpc", "queue run of timer %s in %i seconds (using %s)\n", name, nSeconds, timerInterface->Name());
    deadlineTimers.insert(std::make_pair(name, boost::shared_ptr<RPCTimerBase>(timerInterface->NewTimer(func, nSeconds*1000)))); // �Ͷ�ʱ��������ԣ����뵽��ֹʱ�䶨ʱ��ӳ���б���
}

const CRPCTable tableRPC; // ������ע��ȫ�� RPC ����
