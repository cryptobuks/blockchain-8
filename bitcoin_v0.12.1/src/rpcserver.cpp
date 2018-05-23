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

static bool fRPCRunning = false;
static bool fRPCInWarmup = true;
static std::string rpcWarmupStatus("RPC server started"); // 静态 string 类型全局变量
static CCriticalSection cs_rpcWarmup;
/* Timer-creating functions */
static std::vector<RPCTimerInterface*> timerInterfaces; // RPC 定时器接口列表
/* Map of name to timer.
 * @note Can be changed to std::unique_ptr when C++11 */
static std::map<std::string, boost::shared_ptr<RPCTimerBase> > deadlineTimers;

static struct CRPCSignals
{
    boost::signals2::signal<void ()> Started;
    boost::signals2::signal<void ()> Stopped;
    boost::signals2::signal<void (const CRPCCommand&)> PreCommand;
    boost::signals2::signal<void (const CRPCCommand&)> PostCommand;
} g_rpcSignals;

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
    if (!value.isNum() && !value.isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
    CAmount amount;
    if (!ParseFixedPoint(value.getValStr(), 8, &amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    if (!MoneyRange(amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
    return amount;
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
// 该接口可能会改变
std::string CRPCTable::help(const std::string& strCommand) const
{
    string strRet; // 保存最终的返回结果
    string category; // 类别
    set<rpcfn_type> setDone; // 方法对应的回调函数
    vector<pair<string, const CRPCCommand*> > vCommands; // 命令列表

    for (map<string, const CRPCCommand*>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end(); ++mi)
        vCommands.push_back(make_pair(mi->second->category + mi->first, mi->second)); // <category+name, const CRPCCommand*>
    sort(vCommands.begin(), vCommands.end()); // 按 key 升序排序

    BOOST_FOREACH(const PAIRTYPE(string, const CRPCCommand*)& command, vCommands)
    { // 遍历列表中的命令
        const CRPCCommand *pcmd = command.second; // 取得 RPC 命令指针
        string strMethod = pcmd->name; // 获得方法名
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != string::npos) // 方法名中含有 "label"
            continue; // 则跳过
        if ((strCommand != "" || pcmd->category == "hidden") && strMethod != strCommand) // 指定的命令非空 或 类别为 "hidden" 且 方法名不等于指定命令名
            continue; // 则跳过
        try
        {
            UniValue params;
            rpcfn_type pfn = pcmd->actor; // 注册对应回调函数
            if (setDone.insert(pfn).second) // 若执行列表插入回调成功
                (*pfn)(params, true); // 传入参数并执行该回调，同时标记 fHelp 为 true
        }
        catch (const std::exception& e)
        {
            // Help text is returned in an exception
            string strHelp = string(e.what()); // 拿到回掉函数抛出的异常（帮助）信息
            if (strCommand == "") // 如果指定命令为空即未指定命令
            {
                if (strHelp.find('\n') != string::npos) // 若帮助信息中存在 '\n'
                    strHelp = strHelp.substr(0, strHelp.find('\n')); // 截取第一个 '\n' 之前的的字符串（命令名）

                if (category != pcmd->category) // 类别不同，category 初始化为空
                {
                    if (!category.empty()) // category 非空
                        strRet += "\n"; // 加入换行（初始类别为空）
                    category = pcmd->category; // 拿到类别
                    string firstLetter = category.substr(0,1); // 截取类别首字母
                    boost::to_upper(firstLetter); // 转换为大写字母
                    strRet += "== " + firstLetter + category.substr(1) + " ==\n"; // 拼接首字母大写的类别到返回的结果
                }
            }
            strRet += strHelp + "\n"; // 拼接 RPC 命令名
        }
    } // 重复以上过程，直至遍历完每一个注册的 RPC 命令
    if (strRet == "") // 返回值为空表示指定了未知命令
        strRet = strprintf("help: unknown command: %s\n", strCommand); // 拼接错误信息
    strRet = strRet.substr(0,strRet.size()-1); // 去除结尾的 '\n'
    return strRet; // 返回结果
}

UniValue help(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1) // 参数最多为 1 个（RPC 命令）
        throw runtime_error( // 命令帮助反馈
            "help ( \"command\" )\n"
            "\nList all commands, or get help for a specified command.\n"
            "\nArguments:\n"
            "1. \"command\"     (string, optional) The command to get help on\n"
            "\nResult:\n"
            "\"text\"     (string) The help text\n"
        );

    string strCommand;
    if (params.size() > 0) // 若带有参数
        strCommand = params[0].get_str(); // 获取命令参数的字符串

    return tableRPC.help(strCommand); // 传入命令（可能为空）并返回
}


UniValue stop(const UniValue& params, bool fHelp)
{
    // Accept the deprecated and ignored 'detach' boolean argument
    if (fHelp || params.size() > 1) // 参数最多为 1 个，这里已经过时，现无参数
        throw runtime_error(
            "stop\n"
            "\nStop Bitcoin server.");
    // Event loop will exit after current HTTP requests have been handled, so
    // this reply will get back to the client. // 在当前 HTTP 请求被处理后时间循环才会退出
    StartShutdown(); // 关闭比特币核心服务
    return "Bitcoin server stopping"; // 返回停止信息
}

/**
 * Call Table
 */ // 调用列表
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

CRPCTable::CRPCTable()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++)
    { // 遍历上面定义的 RPC 调用列表
        const CRPCCommand *pcmd; // RPC 命令指针

        pcmd = &vRPCCommands[vcidx]; // 指向一条 RPC 命令
        mapCommands[pcmd->name] = pcmd; // 把该命令注册到 RPC 命令列表中
    }
}

const CRPCCommand *CRPCTable::operator[](const std::string &name) const
{
    map<string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

bool StartRPC()
{
    LogPrint("rpc", "Starting RPC\n");
    fRPCRunning = true; // 设置 RPC 运行状态为 true
    g_rpcSignals.Started(); // 此版本未找到信号注册 pending
    return true;
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
    return fRPCRunning;
}

void SetRPCWarmupStatus(const std::string& newStatus)
{
    LOCK(cs_rpcWarmup);
    rpcWarmupStatus = newStatus; // 设置新状态
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
    // Parse request
    if (!valRequest.isObject())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const UniValue& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    UniValue valMethod = find_value(request, "method");
    if (valMethod.isNull())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (!valMethod.isStr())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
    if (strMethod != "getblocktemplate")
        LogPrint("rpc", "ThreadRPCServer method=%s\n", SanitizeString(strMethod));

    // Parse params
    UniValue valParams = find_value(request, "params");
    if (valParams.isArray())
        params = valParams.get_array();
    else if (valParams.isNull())
        params = UniValue(UniValue::VARR);
    else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
}

static UniValue JSONRPCExecOne(const UniValue& req)
{
    UniValue rpc_result(UniValue::VOBJ);

    JSONRequest jreq;
    try {
        jreq.parse(req);

        UniValue result = tableRPC.execute(jreq.strMethod, jreq.params);
        rpc_result = JSONRPCReplyObj(result, NullUniValue, jreq.id);
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

    return rpc_result;
}

std::string JSONRPCExecBatch(const UniValue& vReq)
{
    UniValue ret(UniValue::VARR);
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));

    return ret.write() + "\n";
}

UniValue CRPCTable::execute(const std::string &strMethod, const UniValue &params) const
{
    // Return immediately if in warmup
    {
        LOCK(cs_rpcWarmup);
        if (fRPCInWarmup)
            throw JSONRPCError(RPC_IN_WARMUP, rpcWarmupStatus);
    }

    // Find method
    const CRPCCommand *pcmd = tableRPC[strMethod];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");

    g_rpcSignals.PreCommand(*pcmd);

    try
    {
        // Execute
        return pcmd->actor(params, false);
    }
    catch (const std::exception& e)
    {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }

    g_rpcSignals.PostCommand(*pcmd);
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
    timerInterfaces.push_back(iface); // 加入定时器接口列表
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
    deadlineTimers.erase(name);
    RPCTimerInterface* timerInterface = timerInterfaces.back();
    LogPrint("rpc", "queue run of timer %s in %i seconds (using %s)\n", name, nSeconds, timerInterface->Name());
    deadlineTimers.insert(std::make_pair(name, boost::shared_ptr<RPCTimerBase>(timerInterface->NewTimer(func, nSeconds*1000))));
}

const CRPCTable tableRPC;
