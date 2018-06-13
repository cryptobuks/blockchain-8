// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "base58.h"
#include "chain.h"
#include "core_io.h"
#include "init.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "policy/rbf.h"
#include "rpcserver.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet.h"
#include "walletdb.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp>

#include <univalue.h>

using namespace std;

int64_t nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

std::string HelpRequiringPassphrase()
{
    return pwalletMain && pwalletMain->IsCrypted()
        ? "\nRequires wallet passphrase to be set with walletpassphrase call."
        : "";
}

bool EnsureWalletIsAvailable(bool avoidException)
{
    if (!pwalletMain) // 若当前钱包未创建
    {
        if (!avoidException)
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (disabled)");
        else
            return false;
    }
    return true; // 钱包创建了直接返回 true
}

void EnsureWalletIsUnlocked()
{
    if (pwalletMain->IsLocked()) // 若钱包加密
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first."); // 抛出错误信息
}

void WalletTxToJSON(const CWalletTx& wtx, UniValue& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry.push_back(Pair("confirmations", confirms)); // 确认数
    if (wtx.IsCoinBase())
        entry.push_back(Pair("generated", true)); // 为创币交易
    if (confirms > 0) // 已上链
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex())); // 区块哈希
        entry.push_back(Pair("blockindex", wtx.nIndex)); // 交易索引
        entry.push_back(Pair("blocktime", mapBlockIndex[wtx.hashBlock]->GetBlockTime())); // 区块创建时间
    } else { // 还在内存池中（未上链）
        entry.push_back(Pair("trusted", wtx.IsTrusted())); // 该交易可信
    }
    uint256 hash = wtx.GetHash();
    entry.push_back(Pair("txid", hash.GetHex())); // 交易索引
    UniValue conflicts(UniValue::VARR);
    BOOST_FOREACH(const uint256& conflict, wtx.GetConflicts())
        conflicts.push_back(conflict.GetHex());
    entry.push_back(Pair("walletconflicts", conflicts)); // 钱包冲突
    entry.push_back(Pair("time", wtx.GetTxTime())); // 交易发起时间
    entry.push_back(Pair("timereceived", (int64_t)wtx.nTimeReceived)); // 交易接收时间

    // Add opt-in RBF status // 添加选择性的 RBF 状态
    std::string rbfStatus = "no";
    if (confirms <= 0) {
        LOCK(mempool.cs);
        if (!mempool.exists(hash)) {
            if (SignalsOptInRBF(wtx)) {
                rbfStatus = "yes";
            } else {
                rbfStatus = "unknown";
            }
        } else if (IsRBFOptIn(*mempool.mapTx.find(hash), mempool)) {
            rbfStatus = "yes";
        }
    }
    entry.push_back(Pair("bip125-replaceable", rbfStatus));

    BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

string AccountFromValue(const UniValue& value) // 从参数中获取账户名
{
    string strAccount = value.get_str(); // 把 UniValue 类型的参数转化为 std::string 类型
    if (strAccount == "*") // 账户名不能为 "*"
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount; // 返回获取的账户名，可能为空
}

UniValue getnewaddress(const UniValue& params, bool fHelp) // 在指定账户下新建一个地址，若不指定账户，默认添加到""空账户下
{
    if (!EnsureWalletIsAvailable(fHelp)) // 1.确保钱包可用，即钱包已创建成功
        return NullUniValue;
    
    if (fHelp || params.size() > 1) // 参数个数为 0 或 1，即要么使用默认账户，要么指定账户
        throw runtime_error( // 2.查看该命令的帮助或命令参数个数超过 1 个均返回该命令的帮助
            "getnewaddress ( \"account\" )\n"
            "\nReturns a new Bitcoin address for receiving payments.\n"
            "If 'account' is specified (DEPRECATED), it is added to the address book \n"
            "so payments received with the address will be credited to 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"        (string, optional) DEPRECATED. The account name for the address to be linked to. If not provided, the default account \"\" is used. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.\n"
            "\nResult:\n"
            "\"bitcoinaddress\"    (string) The new bitcoin address\n"
            "\nExamples:\n"
            + HelpExampleCli("getnewaddress", "")
            + HelpExampleRpc("getnewaddress", "")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 3.对钱包加锁

    // Parse the account first so we don't generate a key if there's an error
    string strAccount; // 用于保存帐户名
    if (params.size() > 0) // 有 1 个参数的情况
        strAccount = AccountFromValue(params[0]); // 4.解析第一个参数并将其作为账户名

    if (!pwalletMain->IsLocked()) // 检查钱包是否上锁（被用户加密）
        pwalletMain->TopUpKeyPool(); // 5.填充密钥池

    // Generate a new key that is added to wallet
    CPubKey newKey; // 6.生成一个新密钥并添加到钱包，返回一个对应的比特币地址
    if (!pwalletMain->GetKeyFromPool(newKey)) // 获取一个公钥
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID(); // 对 65 bytes 的公钥调用 hash160(即先 sha256, 再 ripemd160)

    pwalletMain->SetAddressBook(keyID, strAccount, "receive");

    return CBitcoinAddress(keyID).ToString(); // 160 位的公钥转化为公钥地址：Base58(1 + 20 + 4 bytes)
}


CBitcoinAddress GetAccountAddress(string strAccount, bool bForceNew=false)
{
    CWalletDB walletdb(pwalletMain->strWalletFile); // 创建钱包数据库对象

    CAccount account;
    walletdb.ReadAccount(strAccount, account); // 从数据库中获取指定账户的数据

    bool bKeyUsed = false; // 该密钥是否正在使用标志

    // Check if the current key has been used
    if (account.vchPubKey.IsValid()) // 若该公钥有效
    {
        CScript scriptPubKey = GetScriptForDestination(account.vchPubKey.GetID());
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin();
             it != pwalletMain->mapWallet.end() && account.vchPubKey.IsValid();
             ++it)
        {
            const CWalletTx& wtx = (*it).second;
            BOOST_FOREACH(const CTxOut& txout, wtx.vout) // 遍历交易输出集
                if (txout.scriptPubKey == scriptPubKey) // 若公钥脚本一致
                    bKeyUsed = true; // 标志置为 true
        }
    }

    // Generate a new key
    if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed) // 无效时生成新密钥
    {
        if (!pwalletMain->GetKeyFromPool(account.vchPubKey)) // 从密钥池中获取一个密钥的公钥
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

        pwalletMain->SetAddressBook(account.vchPubKey.GetID(), strAccount, "receive"); // 设置地址簿
        walletdb.WriteAccount(strAccount, account); // 把该账户写入钱包数据库中
    }

    return CBitcoinAddress(account.vchPubKey.GetID()); // 获取公钥对应的索引并返回
}

UniValue getaccountaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // 参数必须为 1 个
        throw runtime_error( // 命令帮助反馈
            "getaccountaddress \"account\"\n"
            "\nDEPRECATED. Returns the current Bitcoin address for receiving payments to this account.\n"
            "\nArguments:\n"
            "1. \"account\"       (string, required) The account name for the address. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created and a new address created  if there is no account by the given name.\n"
            "\nResult:\n"
            "\"bitcoinaddress\"   (string) The account bitcoin address\n"
            "\nExamples:\n"
            + HelpExampleCli("getaccountaddress", "")
            + HelpExampleCli("getaccountaddress", "\"\"")
            + HelpExampleCli("getaccountaddress", "\"myaccount\"")
            + HelpExampleRpc("getaccountaddress", "\"myaccount\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = AccountFromValue(params[0]); // 首先解析账户，如果这里出错我们不会生成一个密钥

    UniValue ret(UniValue::VSTR);

    ret = GetAccountAddress(strAccount).ToString(); // 获取指定账户的找零地址
    return ret; // 返回一个比特币地址
}


UniValue getrawchangeaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() > 1) // 没有参数，这里错了
        throw runtime_error( // 命令帮助反馈
            "getrawchangeaddress\n"
            "\nReturns a new Bitcoin address, for receiving change.\n"
            "This is for use with raw transactions, NOT normal use.\n"
            "\nResult:\n"
            "\"address\"    (string) The address\n"
            "\nExamples:\n"
            + HelpExampleCli("getrawchangeaddress", "")
            + HelpExampleRpc("getrawchangeaddress", "")
       );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    if (!pwalletMain->IsLocked()) // 若当前钱包处于未加密状态
        pwalletMain->TopUpKeyPool(); // 填充密钥池

    CReserveKey reservekey(pwalletMain); // 创建一个密钥池条目
    CPubKey vchPubKey;
    if (!reservekey.GetReservedKey(vchPubKey)) // 获取一个密钥池中的密钥的公钥
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    reservekey.KeepKey(); // 从密钥池中移除获取的密钥，并清空密钥池条目信息

    CKeyID keyID = vchPubKey.GetID(); // 获取公钥索引

    return CBitcoinAddress(keyID).ToString(); // Base58 编码获取公钥地址并返回
}


UniValue setaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保钱包当前可用
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 2) // 参数为 1 或 2 个
        throw runtime_error( // 命令帮助反馈
            "setaccount \"bitcoinaddress\" \"account\"\n"
            "\nDEPRECATED. Sets the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"bitcoinaddress\"  (string, required) The bitcoin address to be associated with an account.\n"
            "2. \"account\"         (string, required) The account to assign the address to.\n"
            "\nExamples:\n"
            + HelpExampleCli("setaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"tabby\"")
            + HelpExampleRpc("setaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", \"tabby\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    CBitcoinAddress address(params[0].get_str()); // 获取指定的比特币地址
    if (!address.IsValid()) // 验证地址是否有效
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");

    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]); // 获取指定的账户

    // Only add the account if the address is yours. // 如果该地址是你的，只需添加账户
    if (IsMine(*pwalletMain, address.Get())) // 若该地址是我的
    {
        // Detect when changing the account of an address that is the 'unused current key' of another account: // 侦测到
        if (pwalletMain->mapAddressBook.count(address.Get())) // 若该地址在地址簿中
        {
            string strOldAccount = pwalletMain->mapAddressBook[address.Get()].name; // 获取地址关联的旧账户名
            if (address == GetAccountAddress(strOldAccount)) // 若旧账户关联的地址为指定地址
                GetAccountAddress(strOldAccount, true); // 先在旧账户下生成一个新地址
        }
        pwalletMain->SetAddressBook(address.Get(), strAccount, "receive"); // 再把该地址关联到指定账户
    }
    else
        throw JSONRPCError(RPC_MISC_ERROR, "setaccount can only be used with own address");

    return NullUniValue; // 返回空值
}


UniValue getaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // 参数必须为 1 个
        throw runtime_error( // 命令帮助反馈
            "getaccount \"bitcoinaddress\"\n"
            "\nDEPRECATED. Returns the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"bitcoinaddress\"  (string, required) The bitcoin address for account lookup.\n"
            "\nResult:\n"
            "\"accountname\"        (string) the account address\n"
            "\nExamples:\n"
            + HelpExampleCli("getaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\"")
            + HelpExampleRpc("getaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    CBitcoinAddress address(params[0].get_str()); // 获取指定的比特币地址
    if (!address.IsValid()) // 检测地址是否有效
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");

    string strAccount; // 保存账户名
    map<CTxDestination, CAddressBookData>::iterator mi = pwalletMain->mapAddressBook.find(address.Get()); // 获取地址簿中对应地址索引的数据
    if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.name.empty()) // 若存在该数据且账户名非空
        strAccount = (*mi).second.name; // 获取账户名
    return strAccount; // 返回所属账户名
}


UniValue getaddressesbyaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // 参数必须为 1 个
        throw runtime_error( // 命令参数反馈
            "getaddressesbyaccount \"account\"\n"
            "\nDEPRECATED. Returns the list of addresses for the given account.\n"
            "\nArguments:\n"
            "1. \"account\"  (string, required) The account name.\n"
            "\nResult:\n"
            "[                     (json array of string)\n"
            "  \"bitcoinaddress\"  (string) a bitcoin address associated with the given account\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressesbyaccount", "\"tabby\"")
            + HelpExampleRpc("getaddressesbyaccount", "\"tabby\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    string strAccount = AccountFromValue(params[0]); // 获取指定账户名

    // Find all addresses that have the given account // 查找基于给定帐户名的所有地址
    UniValue ret(UniValue::VARR); // 创建数组类型的结果对象
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, CAddressBookData)& item, pwalletMain->mapAddressBook)
    { // 遍历地址簿
        const CBitcoinAddress& address = item.first; // 获取比特币地址
        const string& strName = item.second.name; // 获取账户名
        if (strName == strAccount) // 若与指定帐户名相同
            ret.push_back(address.ToString()); // 把该地址加入结果集
    }
    return ret; // 返回结果对象
}

static void SendMoney(const CTxDestination &address, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew)
{
    CAmount curBalance = pwalletMain->GetBalance(); // 获取钱包余额

    // Check amount // 检查发送的金额
    if (nValue <= 0) // 该金额必须为正数
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > curBalance) // 要发送的金额不能大于当前钱包余额
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    // Parse Bitcoin address // 解析比特币地址
    CScript scriptPubKey = GetScriptForDestination(address); // 从目标地址中获取脚本

    // Create and send the transaction // 创建并发送交易
    CReserveKey reservekey(pwalletMain); // 初始化一个密钥池密钥对象
    CAmount nFeeRequired; // 所需交易费
    std::string strError; // 错误信息
    vector<CRecipient> vecSend; // 发送列表
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, fSubtractFeeFromAmount}; // 初始化一个接收者对象
    vecSend.push_back(recipient); // 加入发送列表
    if (!pwalletMain->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError)) { // 创建一笔交易
        if (!fSubtractFeeFromAmount && nValue + nFeeRequired > pwalletMain->GetBalance()) // 若发送金额不包含交易费，发送金额与交易费的和不能大于钱包余额
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    if (!pwalletMain->CommitTransaction(wtxNew, reservekey)) // 提交交易
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
}

UniValue sendtoaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 验证钱包当前可用
        return NullUniValue;
    
    if (fHelp || params.size() < 2 || params.size() > 5) // 参数至少为 2 个，至多为 5 个
        throw runtime_error( // 命令帮助反馈
            "sendtoaddress \"bitcoinaddress\" amount ( \"comment\" \"comment-to\" subtractfeefromamount )\n"
            "\nSend an amount to a given address.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"bitcoinaddress\"  (string, required) The bitcoin address to send to.\n"
            "2. \"amount\"      (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"comment\"     (string, optional) A comment used to store what the transaction is for. \n"
            "                             This is not part of the transaction, just kept in your wallet.\n"
            "4. \"comment-to\"  (string, optional) A comment to store the name of the person or organization \n"
            "                             to which you're sending the transaction. This is not part of the \n"
            "                             transaction, just kept in your wallet.\n"
            "5. subtractfeefromamount  (boolean, optional, default=false) The fee will be deducted from the amount being sent.\n"
            "                             The recipient will receive less bitcoins than you enter in the amount field.\n"
            "\nResult:\n"
            "\"transactionid\"  (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1")
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"donation\" \"seans outpost\"")
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"\" \"\" true")
            + HelpExampleRpc("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.1, \"donation\", \"seans outpost\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    CBitcoinAddress address(params[0].get_str()); // 获取指定的比特币地址
    if (!address.IsValid()) // 验证地址是否有效
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");

    // Amount
    CAmount nAmount = AmountFromValue(params[1]); // 获取转账金额
    if (nAmount <= 0) // 金额不能小于等于 0
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    // Wallet comments // 钱包备注
    CWalletTx wtx; // 一个钱包交易对象
    if (params.size() > 2 && !params[2].isNull() && !params[2].get_str().empty())
        wtx.mapValue["comment"] = params[2].get_str(); // 交易备注
    if (params.size() > 3 && !params[3].isNull() && !params[3].get_str().empty())
        wtx.mapValue["to"]      = params[3].get_str(); // 交易的个人或组织名备注

    bool fSubtractFeeFromAmount = false; // 扣除交易费标志，默认关闭
    if (params.size() > 4)
        fSubtractFeeFromAmount = params[4].get_bool(); // 获取设置

    EnsureWalletIsUnlocked(); // 确保当前钱包处于解密状态

    SendMoney(address.Get(), nAmount, fSubtractFeeFromAmount, wtx); // 发送金额到指定地址

    return wtx.GetHash().GetHex(); // 获取交易哈希，转化为 16 进制并返回
}

UniValue listaddressgroupings(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp) // 没有参数
        throw runtime_error( // 命令帮助反馈
            "listaddressgroupings\n"
            "\nLists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions\n"
            "\nResult:\n"
            "[\n"
            "  [\n"
            "    [\n"
            "      \"bitcoinaddress\",     (string) The bitcoin address\n"
            "      amount,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"account\"             (string, optional) The account (DEPRECATED)\n"
            "    ]\n"
            "    ,...\n"
            "  ]\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listaddressgroupings", "")
            + HelpExampleRpc("listaddressgroupings", "")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    UniValue jsonGroupings(UniValue::VARR); // 创建数组类型结果对象
    map<CTxDestination, CAmount> balances = pwalletMain->GetAddressBalances(); // 获取地址余额映射列表
    BOOST_FOREACH(set<CTxDestination> grouping, pwalletMain->GetAddressGroupings()) // 遍历地址分组集合
    {
        UniValue jsonGrouping(UniValue::VARR);
        BOOST_FOREACH(CTxDestination address, grouping) // 遍历一个地址分组
        {
            UniValue addressInfo(UniValue::VARR);
            addressInfo.push_back(CBitcoinAddress(address).ToString()); // 获取地址
            addressInfo.push_back(ValueFromAmount(balances[address])); // 获取地址余额
            {
                if (pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get()) != pwalletMain->mapAddressBook.end()) // 若在地址簿中找到该地址
                    addressInfo.push_back(pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get())->second.name); // 把该地址关联的账户名加入地址信息
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings; // 返回结果集
}

UniValue signmessage(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "signmessage \"bitcoinaddress\" \"message\"\n"
            "\nSign a message with the private key of an address"
            + HelpRequiringPassphrase() + "\n"
            "\nArguments:\n"
            "1. \"bitcoinaddress\"  (string, required) The bitcoin address to use for the private key.\n"
            "2. \"message\"         (string, required) The message to create a signature of.\n"
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", \"my message\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    string strMessage = params[1].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CKey key;
    if (!pwalletMain->GetKey(keyID, key))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

UniValue getreceivedbyaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 2) // 参数为 1 或 2 个
        throw runtime_error( // 命令帮助反馈
            "getreceivedbyaddress \"bitcoinaddress\" ( minconf )\n"
            "\nReturns the total amount received by the given bitcoinaddress in transactions with at least minconf confirmations.\n"
            "\nArguments:\n"
            "1. \"bitcoinaddress\"  (string, required) The bitcoin address for transactions.\n"
            "2. minconf             (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount   (numeric) The total amount in " + CURRENCY_UNIT + " received at this address.\n"
            "\nExamples:\n"
            "\nThe amount from transactions with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\"") +
            "\nThe amount including unconfirmed transactions, zero confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" 0") +
            "\nThe amount with at least 6 confirmation, very safe\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", 6")
       );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    // Bitcoin address
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str()); // 获取指定的比特币地址
    if (!address.IsValid()) // 判断该地址是否有效
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    CScript scriptPubKey = GetScriptForDestination(address.Get()); // 获取公钥脚本
    if (!IsMine(*pwalletMain,scriptPubKey)) // 检查是否属于自己
        return (double)0.0;

    // Minimum confirmations // 最小确认数
    int nMinDepth = 1; // 最小深度，默认为 1
    if (params.size() > 1)
        nMinDepth = params[1].get_int(); // 获取指定的确认数

    // Tally // 总计
    CAmount nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) // 遍历钱包交易映射列表
    {
        const CWalletTx& wtx = (*it).second; // 获取钱包交易
        if (wtx.IsCoinBase() || !CheckFinalTx(wtx)) // 若为创币交易 或 非最后一笔交易
            continue; // 跳过

        BOOST_FOREACH(const CTxOut& txout, wtx.vout) // 遍历交易输出列表
            if (txout.scriptPubKey == scriptPubKey) // 若输出脚本为指定地址的公钥脚本
                if (wtx.GetDepthInMainChain() >= nMinDepth) // 且交易深度大于等于最小深度
                    nAmount += txout.nValue; // 累加交易金额
    }

    return  ValueFromAmount(nAmount); // 这里直接格式化 Satoshi 返回
}


UniValue getreceivedbyaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 2) // 参数为 1 个或 2 个
        throw runtime_error( // 命令参数反馈
            "getreceivedbyaccount \"account\" ( minconf )\n"
            "\nDEPRECATED. Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.\n"
            "\nArguments:\n"
            "1. \"account\"      (string, required) The selected account, may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nAmount received by the default account with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaccount", "\"\"") +
            "\nAmount received at the tabby account including unconfirmed amounts with zero confirmations\n"
            + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 0") +
            "\nThe amount with at least 6 confirmation, very safe\n"
            + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getreceivedbyaccount", "\"tabby\", 6")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    // Minimum confirmations // 最小确认数
    int nMinDepth = 1; // 最小深度，默认为 1
    if (params.size() > 1)
        nMinDepth = params[1].get_int(); // 获取指定确认数作为最小深度

    // Get the set of pub keys assigned to account // 获取指定账户的公钥集合
    string strAccount = AccountFromValue(params[0]); // 获取指定账户
    set<CTxDestination> setAddress = pwalletMain->GetAccountAddresses(strAccount); // 获取指定账户的地址集合

    // Tally // 总计
    CAmount nAmount = 0; // int64_t
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) // 遍历钱包交易映射列表
    {
        const CWalletTx& wtx = (*it).second; // 获取钱包交易
        if (wtx.IsCoinBase() || !CheckFinalTx(wtx)) // 若为创币交易 或 非最终交易
            continue; // 跳过

        BOOST_FOREACH(const CTxOut& txout, wtx.vout) // 遍历该交易的输出列表
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*pwalletMain, address) && setAddress.count(address)) // 若从输出公钥脚本中提取地址 且 该地址为自己的 且 属于指定账户地址集
                if (wtx.GetDepthInMainChain() >= nMinDepth) // 且交易深度大于最小深度
                    nAmount += txout.nValue; // 累加输出的金额
        }
    }

    return (double)nAmount / (double)COIN; // 换算单位 Satoshi 为 BTC
}


CAmount GetAccountBalance(CWalletDB& walletdb, const string& strAccount, int nMinDepth, const isminefilter& filter)
{
    CAmount nBalance = 0;

    // Tally wallet transactions
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (!CheckFinalTx(wtx) || wtx.GetBlocksToMaturity() > 0 || wtx.GetDepthInMainChain() < 0)
            continue;

        CAmount nReceived, nSent, nFee;
        wtx.GetAccountAmounts(strAccount, nReceived, nSent, nFee, filter);

        if (nReceived != 0 && wtx.GetDepthInMainChain() >= nMinDepth)
            nBalance += nReceived;
        nBalance -= nSent + nFee;
    }

    // Tally internal accounting entries
    nBalance += walletdb.GetAccountCreditDebit(strAccount);

    return nBalance;
}

CAmount GetAccountBalance(const string& strAccount, int nMinDepth, const isminefilter& filter)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);
    return GetAccountBalance(walletdb, strAccount, nMinDepth, filter);
}


UniValue getbalance(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() > 3) // 参数最多为 3 个
        throw runtime_error( // 命令帮助反馈
            "getbalance ( \"account\" minconf includeWatchonly )\n"
            "\nIf account is not specified, returns the server's total available balance.\n"
            "If account is specified (DEPRECATED), returns the balance in the account.\n"
            "Note that the account \"\" is not the same as leaving the parameter out.\n"
            "The server total may be different to the balance in the default \"\" account.\n"
            "\nArguments:\n"
            "1. \"account\"      (string, optional) DEPRECATED. The selected account, or \"*\" for entire wallet. It may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "3. includeWatchonly (bool, optional, default=false) Also include balance in watchonly addresses (see 'importaddress')\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nThe total amount in the wallet\n"
            + HelpExampleCli("getbalance", "") +
            "\nThe total amount in the wallet at least 5 blocks confirmed\n"
            + HelpExampleCli("getbalance", "\"*\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getbalance", "\"*\", 6")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    if (params.size() == 0) // 若无参数
        return  ValueFromAmount(pwalletMain->GetBalance()); // 直接返回当前整个钱包的余额

    int nMinDepth = 1; // 最小深度，默认为 1
    if (params.size() > 1)
        nMinDepth = params[1].get_int(); // 获取最小深度
    isminefilter filter = ISMINE_SPENDABLE; // ismine 过滤器
    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY; // 获取 watchonly

    if (params[0].get_str() == "*") { // 若指定账户名为 "*"
        // Calculate total balance a different way from GetBalance() // 以不同于 GetBalance() 的方式计算总余额
        // (GetBalance() sums up all unspent TxOuts) // （GetBalance() 总计全部未花费的输出）
        // getbalance and "getbalance * 1 true" should return the same number // getbalance 和 "getbalance * 1 true" 应该返回相同的数字
        CAmount nBalance = 0;
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
        { // 遍历钱包交易映射列表
            const CWalletTx& wtx = (*it).second; // 获取钱包交易
            if (!CheckFinalTx(wtx) || wtx.GetBlocksToMaturity() > 0 || wtx.GetDepthInMainChain() < 0) // 检测是否为最终交易 或 未成熟 或 所在链深度小于 0
                continue; // 跳过

            CAmount allFee;
            string strSentAccount;
            list<COutputEntry> listReceived; // 接收列表
            list<COutputEntry> listSent; // 发送列表
            wtx.GetAmounts(listReceived, listSent, allFee, strSentAccount, filter); // 获取相应的金额
            if (wtx.GetDepthInMainChain() >= nMinDepth) // 该交易在链上的深度大于等于最小深度
            {
                BOOST_FOREACH(const COutputEntry& r, listReceived) // 遍历接收列表
                    nBalance += r.amount; // 累加金额
            }
            BOOST_FOREACH(const COutputEntry& s, listSent) // 遍历发送列表
                nBalance -= s.amount; // 减去花费的金额
            nBalance -= allFee; // 减去交易费
        }
        return  ValueFromAmount(nBalance); // 得到钱包总余额并返回
    }

    string strAccount = AccountFromValue(params[0]); // 获取指定的账户名

    CAmount nBalance = GetAccountBalance(strAccount, nMinDepth, filter); // 获取账户余额

    return ValueFromAmount(nBalance); // 返回账户余额
}

UniValue getunconfirmedbalance(const UniValue &params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() > 0) // 没有参数
        throw runtime_error( // 命令帮助反馈
                "getunconfirmedbalance\n"
                "Returns the server's total unconfirmed balance\n");

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    return ValueFromAmount(pwalletMain->GetUnconfirmedBalance()); // 获取未确认的余额并返回
}


UniValue movecmd(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() < 3 || params.size() > 5) // 参数至少 3 个，至多 5 个
        throw runtime_error( // 命令帮助反馈
            "move \"fromaccount\" \"toaccount\" amount ( minconf \"comment\" )\n"
            "\nDEPRECATED. Move a specified amount from one account in your wallet to another.\n"
            "\nArguments:\n"
            "1. \"fromaccount\"   (string, required) The name of the account to move funds from. May be the default account using \"\".\n"
            "2. \"toaccount\"     (string, required) The name of the account to move funds to. May be the default account using \"\".\n"
            "3. amount            (numeric) Quantity of " + CURRENCY_UNIT + " to move between accounts.\n"
            "4. minconf           (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
            "5. \"comment\"       (string, optional) An optional comment, stored in the wallet only.\n"
            "\nResult:\n"
            "true|false           (boolean) true if successful.\n"
            "\nExamples:\n"
            "\nMove 0.01 " + CURRENCY_UNIT + " from the default account to the account named tabby\n"
            + HelpExampleCli("move", "\"\" \"tabby\" 0.01") +
            "\nMove 0.01 " + CURRENCY_UNIT + " timotei to akiko with a comment and funds have 6 confirmations\n"
            + HelpExampleCli("move", "\"timotei\" \"akiko\" 0.01 6 \"happy birthday!\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("move", "\"timotei\", \"akiko\", 0.01, 6, \"happy birthday!\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    string strFrom = AccountFromValue(params[0]); // 起始账户
    string strTo = AccountFromValue(params[1]); // 目标账户
    CAmount nAmount = AmountFromValue(params[2]); // 转账金额
    if (nAmount <= 0) // 转账金额不能小于 0
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    if (params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int(); // 未使用的参数，曾经是最小深度，目前保持类型检查
    string strComment;
    if (params.size() > 4)
        strComment = params[4].get_str(); // 获取备注

    CWalletDB walletdb(pwalletMain->strWalletFile); // 创建钱包数据库对象
    if (!walletdb.TxnBegin()) // 数据库初始化检查
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    int64_t nNow = GetAdjustedTime(); // 获取当前时间

    // Debit // 借出
    CAccountingEntry debit; // 创建账户条目（用于内部转账）借出对象
    debit.nOrderPos = pwalletMain->IncOrderPosNext(&walletdb); // 增加下一条交易的序号
    debit.strAccount = strFrom; // 借出账户
    debit.nCreditDebit = -nAmount; // 金额标记为负数，表示借出
    debit.nTime = nNow; // 记录借出时间
    debit.strOtherAccount = strTo; // 标记借出的目标账户
    debit.strComment = strComment; // 记录备注信息
    pwalletMain->AddAccountingEntry(debit, walletdb); // 把该账户条目加入钱包数据库

    // Credit // 贷入
    CAccountingEntry credit; //  创建账户条目（用于内部转账）贷入对象
    credit.nOrderPos = pwalletMain->IncOrderPosNext(&walletdb); // 增加下一条交易的序号
    credit.strAccount = strTo; // 贷入账户
    credit.nCreditDebit = nAmount; // 金额标记为正数，表示贷入
    credit.nTime = nNow; // 记录到账时间
    credit.strOtherAccount = strFrom; // 标记贷入的起始账户
    credit.strComment = strComment; // 记录备注信息
    pwalletMain->AddAccountingEntry(credit, walletdb); // 把该账户条目加入钱包数据库

    if (!walletdb.TxnCommit()) // 钱包数据库交易提交
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    return true; // 成功返回 true
}


UniValue sendfrom(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() < 3 || params.size() > 6) // 参数至少为 3 个，至多为 6 个
        throw runtime_error( // 命令帮助反馈
            "sendfrom \"fromaccount\" \"tobitcoinaddress\" amount ( minconf \"comment\" \"comment-to\" )\n"
            "\nDEPRECATED (use sendtoaddress). Sent an amount from an account to a bitcoin address."
            + HelpRequiringPassphrase() + "\n"
            "\nArguments:\n"
            "1. \"fromaccount\"       (string, required) The name of the account to send funds from. May be the default account using \"\".\n"
            "2. \"tobitcoinaddress\"  (string, required) The bitcoin address to send funds to.\n"
            "3. amount                (numeric or string, required) The amount in " + CURRENCY_UNIT + " (transaction fee is added on top).\n"
            "4. minconf               (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
            "5. \"comment\"           (string, optional) A comment used to store what the transaction is for. \n"
            "                                     This is not part of the transaction, just kept in your wallet.\n"
            "6. \"comment-to\"        (string, optional) An optional comment to store the name of the person or organization \n"
            "                                     to which you're sending the transaction. This is not part of the transaction, \n"
            "                                     it is just kept in your wallet.\n"
            "\nResult:\n"
            "\"transactionid\"        (string) The transaction id.\n"
            "\nExamples:\n"
            "\nSend 0.01 " + CURRENCY_UNIT + " from the default account to the address, must have at least 1 confirmation\n"
            + HelpExampleCli("sendfrom", "\"\" \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.01") +
            "\nSend 0.01 from the tabby account to the given address, funds must have at least 6 confirmations\n"
            + HelpExampleCli("sendfrom", "\"tabby\" \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.01 6 \"donation\" \"seans outpost\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendfrom", "\"tabby\", \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.01, 6, \"donation\", \"seans outpost\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    string strAccount = AccountFromValue(params[0]); // 获取指定账户
    CBitcoinAddress address(params[1].get_str()); // 获取目标比特币地址
    if (!address.IsValid()) // 验证地址是否有效
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    CAmount nAmount = AmountFromValue(params[2]); // 获取发送金额
    if (nAmount <= 0) // 该金额必须大于 0
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    int nMinDepth = 1; // 最小深度（确认数）
    if (params.size() > 3)
        nMinDepth = params[3].get_int(); // 获取最小确认数

    CWalletTx wtx; // 创建钱包交易
    wtx.strFromAccount = strAccount; // 初始化发送账户
    if (params.size() > 4 && !params[4].isNull() && !params[4].get_str().empty())
        wtx.mapValue["comment"] = params[4].get_str(); // 交易备注
    if (params.size() > 5 && !params[5].isNull() && !params[5].get_str().empty())
        wtx.mapValue["to"]      = params[5].get_str(); // 交易人或组织备注

    EnsureWalletIsUnlocked(); // 确保当前钱包处于为解密状态

    // Check funds // 检查资金
    CAmount nBalance = GetAccountBalance(strAccount, nMinDepth, ISMINE_SPENDABLE); // 获取指定账户余额
    if (nAmount > nBalance) // 发送金额不能大于该账户余额
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    SendMoney(address.Get(), nAmount, false, wtx); // 发送金额

    return wtx.GetHash().GetHex(); // 获取交易哈希，转换为 16 进制并返回
}


UniValue sendmany(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() < 2 || params.size() > 5) // 参数至少为 2 个，至多为 5 个
        throw runtime_error( // 命令帮助反馈
            "sendmany \"fromaccount\" {\"address\":amount,...} ( minconf \"comment\" [\"address\",...] )\n"
            "\nSend multiple times. Amounts are double-precision floating point numbers."
            + HelpRequiringPassphrase() + "\n"
            "\nArguments:\n"
            "1. \"fromaccount\"         (string, required) DEPRECATED. The account to send the funds from. Should be \"\" for the default account\n"
            "2. \"amounts\"             (string, required) A json object with addresses and amounts\n"
            "    {\n"
            "      \"address\":amount   (numeric or string) The bitcoin address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value\n"
            "      ,...\n"
            "    }\n"
            "3. minconf                 (numeric, optional, default=1) Only use the balance confirmed at least this many times.\n"
            "4. \"comment\"             (string, optional) A comment\n"
            "5. subtractfeefromamount   (string, optional) A json array with addresses.\n"
            "                           The fee will be equally deducted from the amount of each selected address.\n"
            "                           Those recipients will receive less bitcoins than you enter in their corresponding amount field.\n"
            "                           If no addresses are specified here, the sender pays the fee.\n"
            "    [\n"
            "      \"address\"            (string) Subtract fee from this address\n"
            "      ,...\n"
            "    ]\n"
            "\nResult:\n"
            "\"transactionid\"          (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
            "                                    the number of addresses.\n"
            "\nExamples:\n"
            "\nSend two amounts to two different addresses:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\"") +
            "\nSend two amounts to two different addresses setting the confirmation and comment:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" 6 \"testing\"") +
            "\nSend two amounts to two different addresses, subtract fee from amount:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" 1 \"\" \"[\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\",\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendmany", "\"\", \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\", 6, \"testing\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    string strAccount = AccountFromValue(params[0]); // 获取指定账户
    UniValue sendTo = params[1].get_obj(); // 获取发送对象（地址和金额）
    int nMinDepth = 1; // 最小深度，默认为 1
    if (params.size() > 2)
        nMinDepth = params[2].get_int(); // 获取最小确认数

    CWalletTx wtx; // 创建一笔钱包交易
    wtx.strFromAccount = strAccount; // 初始化发送账户
    if (params.size() > 3 && !params[3].isNull() && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str(); // 获取交易备注

    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (params.size() > 4)
        subtractFeeFromAmount = params[4].get_array(); // 获取数组类型的从金额中减去交易费

    set<CBitcoinAddress> setAddress; // 比特币地址集
    vector<CRecipient> vecSend; // 发送列表

    CAmount totalAmount = 0; // 要发送的总金额
    vector<string> keys = sendTo.getKeys(); // 获取目的地址列表
    BOOST_FOREACH(const string& name_, keys) // 遍历地址列表
    {
        CBitcoinAddress address(name_); // 比特币地址对象
        if (!address.IsValid()) // 验证地址是否有效
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Bitcoin address: ")+name_);

        if (setAddress.count(address)) // 地址集中不应该存在当前地址，保证发送到的地址不重复
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address); // 插入地址集

        CScript scriptPubKey = GetScriptForDestination(address.Get()); // 从地址获取公钥脚本
        CAmount nAmount = AmountFromValue(sendTo[name_]); // 获取该地址对应的金额
        if (nAmount <= 0) // 金额必须大于 0
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        totalAmount += nAmount; // 累加金额

        bool fSubtractFeeFromAmount = false; // 是否从金额中减去交易费标志，初始化为 false
        for (unsigned int idx = 0; idx < subtractFeeFromAmount.size(); idx++) { // 遍历该对象
            const UniValue& addr = subtractFeeFromAmount[idx]; // 获取地址
            if (addr.get_str() == name_) // 若为指定的目的地址
                fSubtractFeeFromAmount = true; // 标志置为 true
        }

        CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount}; // 初始化一个接收对象
        vecSend.push_back(recipient); // 加入发送列表
    }

    EnsureWalletIsUnlocked(); // 确保当前钱包处于解密状态

    // Check funds // 检查资金
    CAmount nBalance = GetAccountBalance(strAccount, nMinDepth, ISMINE_SPENDABLE); // 获取指定账户余额
    if (totalAmount > nBalance) // 发送总金额不能大于账户余额
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send // 发送
    CReserveKey keyChange(pwalletMain); // 创建一个密钥池中的密钥条目
    CAmount nFeeRequired = 0; // 所需交易费
    int nChangePosRet = -1;
    string strFailReason; // 保存错误信息
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason); // 创建一笔交易
    if (!fCreated) // 检查交易状态
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    if (!pwalletMain->CommitTransaction(wtx, keyChange)) // 提交交易
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

    return wtx.GetHash().GetHex(); // 获取交易哈希，转换为 16 进制并返回
}

// Defined in rpcmisc.cpp
extern CScript _createmultisig_redeemScript(const UniValue& params);

UniValue addmultisigaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() < 2 || params.size() > 3)
    {
        string msg = "addmultisigaddress nrequired [\"key\",...] ( \"account\" )\n"
            "\nAdd a nrequired-to-sign multisignature address to the wallet.\n"
            "Each key is a Bitcoin address or hex-encoded public key.\n"
            "If 'account' is specified (DEPRECATED), assign address to that account.\n"

            "\nArguments:\n"
            "1. nrequired        (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keysobject\"   (string, required) A json array of bitcoin addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"address\"  (string) bitcoin address or hex-encoded public key\n"
            "       ...,\n"
            "     ]\n"
            "3. \"account\"      (string, optional) DEPRECATED. An account to assign the addresses to.\n"

            "\nResult:\n"
            "\"bitcoinaddress\"  (string) A bitcoin address associated with the keys.\n"

            "\nExamples:\n"
            "\nAdd a multisig address from 2 addresses\n"
            + HelpExampleCli("addmultisigaddress", "2 \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("addmultisigaddress", "2, \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"")
        ;
        throw runtime_error(msg);
    }

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]);

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig_redeemScript(params);
    CScriptID innerID(inner);
    pwalletMain->AddCScript(inner);

    pwalletMain->SetAddressBook(innerID, strAccount, "send");
    return CBitcoinAddress(innerID).ToString();
}


struct tallyitem // 账目类
{
    CAmount nAmount; // 金额，默认为 0
    int nConf; // 确认数，默认 int 的最大值
    vector<uint256> txids; // 交易索引列表
    bool fIsWatchonly; // 开启 watchonly 标志，默认关闭
    tallyitem() // 无参构造
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
        fIsWatchonly = false;
    }
};

UniValue ListReceived(const UniValue& params, bool fByAccounts) // fByAccounts = true
{
    // Minimum confirmations // 最低确认数
    int nMinDepth = 1; // 最小深度，默认为 1
    if (params.size() > 0)
        nMinDepth = params[0].get_int(); // 获取最小深度

    // Whether to include empty accounts
    bool fIncludeEmpty = false; // 包含空余额的账户标志，默认为 false
    if (params.size() > 1)
        fIncludeEmpty = params[1].get_bool(); // 获取是否包含空余额的账户标志

    isminefilter filter = ISMINE_SPENDABLE; // 可花费
    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY; // 设置挖矿 watchonly

    // Tally // 记账
    map<CBitcoinAddress, tallyitem> mapTally; // 地址账目映射列表
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    { // 遍历钱包交易映射列表
        const CWalletTx& wtx = (*it).second; // 获取钱包交易

        if (wtx.IsCoinBase() || !CheckFinalTx(wtx)) // 非创币交易 且 为最终交易
            continue;

        int nDepth = wtx.GetDepthInMainChain(); // 获取该交易的链深度
        if (nDepth < nMinDepth) // 深度不能小于最小深度（最低确认数）
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        { // 遍历交易输出列表
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address)) // 通过交易输出公钥脚本获取公钥地址
                continue;

            isminefilter mine = IsMine(*pwalletMain, address);
            if(!(mine & filter))
                continue;

            tallyitem& item = mapTally[address]; // 获取地址对应的账目
            item.nAmount += txout.nValue; // 累加交易输出金额
            item.nConf = min(item.nConf, nDepth); // 获取交易深度
            item.txids.push_back(wtx.GetHash()); // 加入交易索引列表
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }
    }

    // Reply
    UniValue ret(UniValue::VARR); // 创建数组类型的结果对象
    map<string, tallyitem> mapAccountTally; // 账户账目映射列表
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, CAddressBookData)& item, pwalletMain->mapAddressBook) // 遍历地址簿映射列表
    {
        const CBitcoinAddress& address = item.first; // 获取地址
        const string& strAccount = item.second.name; // 获取帐户名
        map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address); // 获取地址对应的账目
        if (it == mapTally.end() && !fIncludeEmpty) // 未找到 且 包含空余额账户标志为 false
            continue; // 跳过

        CAmount nAmount = 0; // 金额
        int nConf = std::numeric_limits<int>::max(); // 确认数，默认最大值
        bool fIsWatchonly = false; // watchonly 标志，默认为 false
        if (it != mapTally.end()) // 找到
        { // 地址对应账目
            nAmount = (*it).second.nAmount; // 获取地址金额
            nConf = (*it).second.nConf; // 获取地址确认数
            fIsWatchonly = (*it).second.fIsWatchonly; // 获取地址 watchonly 标志
        }

        if (fByAccounts) // true
        {
            tallyitem& item = mapAccountTally[strAccount]; // 获取账户名对应的账目
            item.nAmount += nAmount; // 累加金额
            item.nConf = min(item.nConf, nConf); // 获取最小确认数
            item.fIsWatchonly = fIsWatchonly; // 获取 watchonly 标志
        }
        else
        {
            UniValue obj(UniValue::VOBJ);
            if(fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true));
            obj.push_back(Pair("address",       address.ToString()));
            obj.push_back(Pair("account",       strAccount));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            if (!fByAccounts)
                obj.push_back(Pair("label", strAccount));
            UniValue transactions(UniValue::VARR);
            if (it != mapTally.end())
            {
                BOOST_FOREACH(const uint256& item, (*it).second.txids)
                {
                    transactions.push_back(item.GetHex());
                }
            }
            obj.push_back(Pair("txids", transactions));
            ret.push_back(obj);
        }
    }

    if (fByAccounts) // true
    {
        for (map<string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
        { // 遍历账户账目映射列表
            CAmount nAmount = (*it).second.nAmount; // 获取余额
            int nConf = (*it).second.nConf; // 获取确认数
            UniValue obj(UniValue::VOBJ); 
            if((*it).second.fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true)); // watchonly 标志
            obj.push_back(Pair("account",       (*it).first)); // 帐户名
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount))); // 余额
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf))); // 确认数
            ret.push_back(obj); // 加入结果集
        }
    }

    return ret; // 返回结果对象
}

UniValue listreceivedbyaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() > 3) // 参数最多为 3 个
        throw runtime_error( // 命令帮助反馈
            "listreceivedbyaddress ( minconf includeempty includeWatchonly)\n"
            "\nList balances by receiving address.\n"
            "\nArguments:\n"
            "1. minconf       (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. includeempty  (numeric, optional, default=false) Whether to include addresses that haven't received any payments.\n"
            "3. includeWatchonly (bool, optional, default=false) Whether to include watchonly addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,        (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"address\" : \"receivingaddress\",  (string) The receiving address\n"
            "    \"account\" : \"accountname\",       (string) DEPRECATED. The account of the receiving address. The default account is \"\".\n"
            "    \"amount\" : x.xxx,                  (numeric) The total amount in " + CURRENCY_UNIT + " received by the address\n"
            "    \"confirmations\" : n,               (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\"                (string) A comment for the address/transaction, if any\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listreceivedbyaddress", "")
            + HelpExampleCli("listreceivedbyaddress", "6 true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true, true")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    return ListReceived(params, false); // 获取接收金额列表并返回
}

UniValue listreceivedbyaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() > 3) // 参数最多为 3 个
        throw runtime_error( // 命令帮助反馈
            "listreceivedbyaccount ( minconf includeempty includeWatchonly)\n"
            "\nDEPRECATED. List balances by account.\n"
            "\nArguments:\n"
            "1. minconf      (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. includeempty (boolean, optional, default=false) Whether to include accounts that haven't received any payments.\n"
            "3. includeWatchonly (bool, optional, default=false) Whether to include watchonly addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,   (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"account\" : \"accountname\",  (string) The account name of the receiving account\n"
            "    \"amount\" : x.xxx,             (numeric) The total amount received by addresses with this account\n"
            "    \"confirmations\" : n,          (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\"           (string) A comment for the address/transaction, if any\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listreceivedbyaccount", "")
            + HelpExampleCli("listreceivedbyaccount", "6 true")
            + HelpExampleRpc("listreceivedbyaccount", "6, true, true")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    return ListReceived(params, true); // 列出账户余额并返回
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest)
{
    CBitcoinAddress addr;
    if (addr.Set(dest))
        entry.push_back(Pair("address", addr.ToString()));
}

void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, UniValue& ret, const isminefilter& filter)
{
    CAmount nFee; // 交易费
    string strSentAccount; // 发送账户
    list<COutputEntry> listReceived; // 接收输出条目列表
    list<COutputEntry> listSent; // 发送输出条目列表

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter); // 获取相应金额

    bool fAllAccounts = (strAccount == string("*")); // 全部账户标志
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY); // watchonly 标志

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    { // 发送列表非空 或 交易费非 0 且 全部账户 或 发送账户为指定账户（这里是 "*" 表示全部账户）
        BOOST_FOREACH(const COutputEntry& s, listSent) // 遍历发送列表
        {
            UniValue entry(UniValue::VOBJ);
            if(involvesWatchonly || (::IsMine(*pwalletMain, s.destination) & ISMINE_WATCH_ONLY))
                entry.push_back(Pair("involvesWatchonly", true));
            entry.push_back(Pair("account", strSentAccount)); // 发送账户
            MaybePushAddress(entry, s.destination); // 发送地址
            entry.push_back(Pair("category", "send")); // 交易类别为发送
            entry.push_back(Pair("amount", ValueFromAmount(-s.amount))); // 交易金额，符号表示发送
            if (pwalletMain->mapAddressBook.count(s.destination))
                entry.push_back(Pair("label", pwalletMain->mapAddressBook[s.destination].name)); // 标签为帐户名
            entry.push_back(Pair("vout", s.vout)); // 输出索引
            entry.push_back(Pair("fee", ValueFromAmount(-nFee))); // 交易费
            if (fLong) // true
                WalletTxToJSON(wtx, entry); // 钱包交易信息转化为 JSON 格式
            entry.push_back(Pair("abandoned", wtx.isAbandoned())); // 是否被抛弃
            ret.push_back(entry); // 加入交易信息集
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    { // 接收列表非空 且 该交易深度大于等于最小深度（确认数）
        BOOST_FOREACH(const COutputEntry& r, listReceived) // 遍历接收列表
        {
            string account;
            if (pwalletMain->mapAddressBook.count(r.destination)) // 若该地址存在于地址簿
                account = pwalletMain->mapAddressBook[r.destination].name; // 获取地址对应账户名
            if (fAllAccounts || (account == strAccount)) // 全部账户 或 该账户为指定账户（"*"）
            {
                UniValue entry(UniValue::VOBJ);
                if(involvesWatchonly || (::IsMine(*pwalletMain, r.destination) & ISMINE_WATCH_ONLY))
                    entry.push_back(Pair("involvesWatchonly", true));
                entry.push_back(Pair("account", account)); // 账户名
                MaybePushAddress(entry, r.destination); // 接收地址
                if (wtx.IsCoinBase()) // 该交易为创币交易
                {
                    if (wtx.GetDepthInMainChain() < 1) // 该交易在主链上的深度为 0
                        entry.push_back(Pair("category", "orphan")); // 孤儿链
                    else if (wtx.GetBlocksToMaturity() > 0) // 成熟所需区块数大于 0
                        entry.push_back(Pair("category", "immature")); // 未成熟
                    else
                        entry.push_back(Pair("category", "generate")); // regtest 生成
                }
                else
                { // 普通交易（非创币交易）
                    entry.push_back(Pair("category", "receive")); // 交易类别为接收
                }
                entry.push_back(Pair("amount", ValueFromAmount(r.amount))); // 交易金额
                if (pwalletMain->mapAddressBook.count(r.destination)) // 若该地址存在于地址簿
                    entry.push_back(Pair("label", account)); // 标签为该地址对应的帐户名
                entry.push_back(Pair("vout", r.vout)); // 输出索引
                if (fLong)
                    WalletTxToJSON(wtx, entry); // 钱包交易信息转化为 JSON
                ret.push_back(entry); // 加入交易信息集
            }
        }
    }
}

void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, UniValue& ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

UniValue listtransactions(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() > 4) // 参数最多为 4 个
        throw runtime_error( // 命令帮助反馈
            "listtransactions ( \"account\" count from includeWatchonly)\n"
            "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions for account 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"    (string, optional) DEPRECATED. The account name. Should be \"*\".\n"
            "2. count          (numeric, optional, default=10) The number of transactions to return\n"
            "3. from           (numeric, optional, default=0) The number of transactions to skip\n"
            "4. includeWatchonly (bool, optional, default=false) Include transactions to watchonly addresses (see 'importaddress')\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. \n"
            "                                                It will be \"\" for the default account.\n"
            "    \"address\":\"bitcoinaddress\",    (string) The bitcoin address of the transaction. Not present for \n"
            "                                                move transactions (category = move).\n"
            "    \"category\":\"send|receive|move\", (string) The transaction category. 'move' is a local (off blockchain)\n"
            "                                                transaction between accounts, and not associated with an address,\n"
            "                                                transaction id or block. 'send' and 'receive' transactions are \n"
            "                                                associated with an address, transaction id and block details\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the\n"
            "                                         'move' category for moves outbound. It is positive for the 'receive' category,\n"
            "                                         and for the 'move' category for inbound funds.\n"
            "    \"vout\": n,                (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                                         'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and \n"
            "                                         'receive' category of transactions. Negative confirmations indicate the\n"
            "                                         transation conflicts with the block chain\n"
            "    \"trusted\": xxx            (bool) Whether we consider the outputs of this unconfirmed transaction safe to spend.\n"
            "    \"blockhash\": \"hashvalue\", (string) The block hash containing the transaction. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The block index containing the transaction. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\", (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (midnight Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (midnight Jan 1 1970 GMT). Available \n"
            "                                          for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"label\": \"label\"        (string) A comment for the address/transaction, if any\n"
            "    \"otheraccount\": \"accountname\",  (string) For the 'move' category of transactions, the account the funds came \n"
            "                                          from (for receiving funds, positive amounts), or went to (for sending funds,\n"
            "                                          negative amounts).\n"
            "    \"bip125-replaceable\": \"yes|no|unknown\"  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                     may be unknown for unconfirmed transactions not in the mempool\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList the most recent 10 transactions in the systems\n"
            + HelpExampleCli("listtransactions", "") +
            "\nList transactions 100 to 120\n"
            + HelpExampleCli("listtransactions", "\"*\" 20 100") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("listtransactions", "\"*\", 20, 100")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    string strAccount = "*"; // 账户名，默认为 "*" 表示全部账户
    if (params.size() > 0)
        strAccount = params[0].get_str(); // 获取帐户名
    int nCount = 10; // 交易数，默认 10 条
    if (params.size() > 1)
        nCount = params[1].get_int(); // 获取交易数
    int nFrom = 0; // 要跳过的交易数，默认 0 条
    if (params.size() > 2)
        nFrom = params[2].get_int(); // 获取要跳过的交易数
    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 3)
        if(params[3].get_bool())
            filter = filter | ISMINE_WATCH_ONLY; // 设置 watchonly

    if (nCount < 0) // 交易数非负
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0) // 要跳过的交易数非负
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR); // 创建数组类型的结果集

    const CWallet::TxItems & txOrdered = pwalletMain->wtxOrdered; // 获取有序的交易列表

    // iterate backwards until we have nCount items to return: // 向后迭代，直到我们有 nCount 个条目返回
    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    { // 遍历有序的交易列表
        CWalletTx *const pwtx = (*it).second.first; // 获取钱包交易
        if (pwtx != 0)
            ListTransactions(*pwtx, strAccount, 0, true, ret, filter); // 获取交易信息到结果集
        CAccountingEntry *const pacentry = (*it).second.second; // 获取对应的账户条目
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret); // 账户条目转换为 JSON 格式

        if ((int)ret.size() >= (nCount+nFrom)) break; // 若结果集大小大于等于 要获取的交易数量与要跳过交易数量的和，跳出
    }
    // ret is newest to oldest // 结果集是从最新到最旧

    if (nFrom > (int)ret.size()) // 结果集大小小于要跳过的交易数
        nFrom = ret.size(); // 要跳过的交易数等于结果集大小
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    vector<UniValue> arrTmp = ret.getValues(); // 获取结果集中的数组作为临时对象

    vector<UniValue>::iterator first = arrTmp.begin();
    std::advance(first, nFrom); // 增加 first 迭代器 nFrom
    vector<UniValue>::iterator last = arrTmp.begin();
    std::advance(last, nFrom+nCount); // 增加 last 迭代器 nFrom+nCount

    if (last != arrTmp.end()) arrTmp.erase(last, arrTmp.end()); // 擦除尾部多余部分
    if (first != arrTmp.begin()) arrTmp.erase(arrTmp.begin(), first); // 擦除头部多余部分

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest // 反转后为最老到最新，列表从上到下：旧->新

    ret.clear(); // 清空结果集
    ret.setArray(); // 设置为数组类型
    ret.push_backV(arrTmp); // 加入临时数组

    return ret; // 返回结果集
}

UniValue listaccounts(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() > 2) // 参数最多 2 个
        throw runtime_error( // 命令帮助反馈
            "listaccounts ( minconf includeWatchonly)\n"
            "\nDEPRECATED. Returns Object that has account names as keys, account balances as values.\n"
            "\nArguments:\n"
            "1. minconf          (numeric, optional, default=1) Only include transactions with at least this many confirmations\n"
            "2. includeWatchonly (bool, optional, default=false) Include balances in watchonly addresses (see 'importaddress')\n"
            "\nResult:\n"
            "{                      (json object where keys are account names, and values are numeric balances\n"
            "  \"account\": x.xxx,  (numeric) The property name is the account name, and the value is the total balance for the account.\n"
            "  ...\n"
            "}\n"
            "\nExamples:\n"
            "\nList account balances where there at least 1 confirmation\n"
            + HelpExampleCli("listaccounts", "") +
            "\nList account balances including zero confirmation transactions\n"
            + HelpExampleCli("listaccounts", "0") +
            "\nList account balances for 6 or more confirmations\n"
            + HelpExampleCli("listaccounts", "6") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("listaccounts", "6")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    int nMinDepth = 1; // 最小深度
    if (params.size() > 0)
        nMinDepth = params[0].get_int(); // 获取指定深度
    isminefilter includeWatchonly = ISMINE_SPENDABLE;
    if(params.size() > 1)
        if(params[1].get_bool())
            includeWatchonly = includeWatchonly | ISMINE_WATCH_ONLY; // 设置 watchonly

    map<string, CAmount> mapAccountBalances; // 账户余额映射列表
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& entry, pwalletMain->mapAddressBook) { // 遍历地址簿
        if (IsMine(*pwalletMain, entry.first) & includeWatchonly) // This address belongs to me // 该地址属于我
            mapAccountBalances[entry.second.name] = 0; // 加入账户余额映射列表，并初始化余额为 0
    }

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    { // 遍历钱包交易索引列表
        const CWalletTx& wtx = (*it).second; // 获取钱包交易
        CAmount nFee; // 交易费
        string strSentAccount; // 发送账户名
        list<COutputEntry> listReceived; // 接收列表
        list<COutputEntry> listSent; // 发送列表
        int nDepth = wtx.GetDepthInMainChain(); // 获取该交易的深度
        if (wtx.GetBlocksToMaturity() > 0 || nDepth < 0) // 未成熟 或 未上链（深度小于 0）
            continue; // 跳过
        wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, includeWatchonly); // 获取相关金额
        mapAccountBalances[strSentAccount] -= nFee; // 账户余额减去交易费
        BOOST_FOREACH(const COutputEntry& s, listSent) // 遍历发送列表
            mapAccountBalances[strSentAccount] -= s.amount; // 账户余额减去发送的金额
        if (nDepth >= nMinDepth) // 交易深度大于等于最小深度
        {
            BOOST_FOREACH(const COutputEntry& r, listReceived) // 遍历接收列表
                if (pwalletMain->mapAddressBook.count(r.destination)) // 若目标地址存在于地址簿中
                    mapAccountBalances[pwalletMain->mapAddressBook[r.destination].name] += r.amount; // 对应账户余额加上接收金额
                else
                    mapAccountBalances[""] += r.amount; // 否则默认账户余额加上该接收金额
        }
    }

    const list<CAccountingEntry> & acentries = pwalletMain->laccentries; // 获取账户条目列表
    BOOST_FOREACH(const CAccountingEntry& entry, acentries) // 遍历该列表
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit; // 不明

    UniValue ret(UniValue::VOBJ); // 创建对象类型结果
    BOOST_FOREACH(const PAIRTYPE(string, CAmount)& accountBalance, mapAccountBalances) { // 遍历账户余额映射列表
        ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second))); // 账户名和余额配对加入结果集
    }
    return ret; // 返回结果
}

UniValue listsinceblock(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp) // 只处理帮助信息
        throw runtime_error( // 命令帮助反馈
            "listsinceblock ( \"blockhash\" target-confirmations includeWatchonly)\n"
            "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted\n"
            "\nArguments:\n"
            "1. \"blockhash\"   (string, optional) The block hash to list transactions since\n"
            "2. target-confirmations:    (numeric, optional) The confirmations required, must be 1 or more\n"
            "3. includeWatchonly:        (bool, optional, default=false) Include transactions to watchonly addresses (see 'importaddress')"
            "\nResult:\n"
            "{\n"
            "  \"transactions\": [\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. Will be \"\" for the default account.\n"
            "    \"address\":\"bitcoinaddress\",    (string) The bitcoin address of the transaction. Not present for move transactions (category = move).\n"
            "    \"category\":\"send|receive\",     (string) The transaction category. 'send' has negative amounts, 'receive' has positive amounts.\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the 'move' category for moves \n"
            "                                          outbound. It is positive for the 'receive' category, and for the 'move' category for inbound funds.\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the 'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockhash\": \"hashvalue\",     (string) The block hash containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The block index containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\",  (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (Jan 1 1970 GMT). Available for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"label\" : \"label\"       (string) A comment for the address/transaction, if any\n"
            "    \"to\": \"...\",            (string) If a comment to is associated with the transaction.\n"
             "  ],\n"
            "  \"lastblock\": \"lastblockhash\"     (string) The hash of the last block\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("listsinceblock", "")
            + HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6")
            + HelpExampleRpc("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    CBlockIndex *pindex = NULL; // 从某个区块开始
    int target_confirms = 1; // 确认数，默认为 1
    isminefilter filter = ISMINE_SPENDABLE; // watchonly

    if (params.size() > 0) // 有 1 个以上的参数
    {
        uint256 blockId;

        blockId.SetHex(params[0].get_str()); // 获取区块索引
        BlockMap::iterator it = mapBlockIndex.find(blockId); // 在区块索引映射列表中查找该区块
        if (it != mapBlockIndex.end()) // 若找到
            pindex = it->second; // 获取该区块索引指针
    }

    if (params.size() > 1) // 若参数有 2 个以上
    {
        target_confirms = params[1].get_int(); // 获取确认数

        if (target_confirms < 1) // 确认数最小为 1
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    if(params.size() > 2) // 若参数有 3 个以上
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY; // 设置 watchonly

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1; // 获取指定区块的深度

    UniValue transactions(UniValue::VARR); // 创建数组类型的交易信息集

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++) // 遍历钱包交易映射列表
    {
        CWalletTx tx = (*it).second; // 获取钱包交易

        if (depth == -1 || tx.GetDepthInMainChain() < depth) // 若未指定区块 或 该交易深度小于指定区块深度
            ListTransactions(tx, "*", 0, true, transactions, filter); // 以钱包交易为索引获取交易信息集
    }

    CBlockIndex *pblockLast = chainActive[chainActive.Height() + 1 - target_confirms]; // 若确认数为 1，获取最佳区块索引
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : uint256(); // 获取该区块哈希值

    UniValue ret(UniValue::VOBJ); // 对象类型的结果
    ret.push_back(Pair("transactions", transactions)); // 交易集
    ret.push_back(Pair("lastblock", lastblock.GetHex())); // 最佳区块哈希值

    return ret; // 返回结果对象
}

UniValue gettransaction(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 2) // 参数为 1 或 2 个
        throw runtime_error( // 命令帮助反馈
            "gettransaction \"txid\" ( includeWatchonly )\n"
            "\nGet detailed information about in-wallet transaction <txid>\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) The transaction id\n"
            "2. \"includeWatchonly\"    (bool, optional, default=false) Whether to include watchonly addresses in balance calculation and details[]\n"
            "\nResult:\n"
            "{\n"
            "  \"amount\" : x.xxx,        (numeric) The transaction amount in " + CURRENCY_UNIT + "\n"
            "  \"confirmations\" : n,     (numeric) The number of confirmations\n"
            "  \"blockhash\" : \"hash\",  (string) The block hash\n"
            "  \"blockindex\" : xx,       (numeric) The block index\n"
            "  \"blocktime\" : ttt,       (numeric) The time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"txid\" : \"transactionid\",   (string) The transaction id.\n"
            "  \"time\" : ttt,            (numeric) The transaction time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"timereceived\" : ttt,    (numeric) The time received in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"bip125-replaceable\": \"yes|no|unknown\"  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                   may be unknown for unconfirmed transactions not in the mempool\n"
            "  \"details\" : [\n"
            "    {\n"
            "      \"account\" : \"accountname\",  (string) DEPRECATED. The account name involved in the transaction, can be \"\" for the default account.\n"
            "      \"address\" : \"bitcoinaddress\",   (string) The bitcoin address involved in the transaction\n"
            "      \"category\" : \"send|receive\",    (string) The category, either 'send' or 'receive'\n"
            "      \"amount\" : x.xxx,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"label\" : \"label\",              (string) A comment for the address/transaction, if any\n"
            "      \"vout\" : n,                       (numeric) the vout value\n"
            "    }\n"
            "    ,...\n"
            "  ],\n"
            "  \"hex\" : \"data\"         (string) Raw data for transaction\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true")
            + HelpExampleRpc("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    uint256 hash;
    hash.SetHex(params[0].get_str()); // 获取交易哈希

    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 1)
        if(params[1].get_bool())
            filter = filter | ISMINE_WATCH_ONLY; // 设置 watch-only 选项

    UniValue entry(UniValue::VOBJ);
    if (!pwalletMain->mapWallet.count(hash)) // 验证钱包中是否存在该交易
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    const CWalletTx& wtx = pwalletMain->mapWallet[hash]; // 获取索引对应的钱包交易

    CAmount nCredit = wtx.GetCredit(filter); // 贷款金额
    CAmount nDebit = wtx.GetDebit(filter); // 借出金额
    CAmount nNet = nCredit - nDebit; // 净赚
    CAmount nFee = (wtx.IsFromMe(filter) ? wtx.GetValueOut() - nDebit : 0); // 交易费

    entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee))); // 余额
    if (wtx.IsFromMe(filter)) // 如果该交易属于自己（发送）
        entry.push_back(Pair("fee", ValueFromAmount(nFee))); // 余额

    WalletTxToJSON(wtx, entry); // 钱包交易转换为 JSON 格式

    UniValue details(UniValue::VARR);
    ListTransactions(wtx, "*", 0, false, details, filter); // 获取交易细节
    entry.push_back(Pair("details", details)); // 加入细节信息

    string strHex = EncodeHexTx(static_cast<CTransaction>(wtx)); // 对钱包交易进行 16 进制编码
    entry.push_back(Pair("hex", strHex)); // 交易的 16 进制编码形式（非交易索引）

    return entry; // 返回结果对象
}

UniValue abandontransaction(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;

    if (fHelp || params.size() != 1) // 参数必须为 1 个
        throw runtime_error( // 命令帮助反馈
            "abandontransaction \"txid\"\n"
            "\nMark in-wallet transaction <txid> as abandoned\n"
            "This will mark this transaction and all its in-wallet descendants as abandoned which will allow\n"
            "for their inputs to be respent.  It can be used to replace \"stuck\" or evicted transactions.\n"
            "It only works on transactions which are not included in a block and are not currently in the mempool.\n"
            "It has no effect on transactions which are already conflicted or abandoned.\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) The transaction id\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 上锁

    uint256 hash;
    hash.SetHex(params[0].get_str()); // 获取交易索引

    if (!pwalletMain->mapWallet.count(hash)) // 检查指定交易是否在钱包中
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    if (!pwalletMain->AbandonTransaction(hash)) // 标记该钱包交易为已抛弃
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");

    return NullUniValue; // 返回空
}


UniValue backupwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // 参数必须为 1 个
        throw runtime_error( // 命令帮助反馈
            "backupwallet \"destination\"\n"
            "\nSafely copies wallet.dat to destination, which can be a directory or a path with filename.\n"
            "\nArguments:\n"
            "1. \"destination\"   (string) The destination directory or file\n"
            "\nExamples:\n"
            + HelpExampleCli("backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("backupwallet", "\"backup.dat\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    string strDest = params[0].get_str(); // 获取指定的输出目标
    if (!BackupWallet(*pwalletMain, strDest))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");

    return NullUniValue; // 返回空值
}


UniValue keypoolrefill(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保钱包当前可用
        return NullUniValue;
    
    if (fHelp || params.size() > 1) // 至多 1 个参数
        throw runtime_error( // 命令帮助反馈
            "keypoolrefill ( newsize )\n"
            "\nFills the keypool."
            + HelpRequiringPassphrase() + "\n"
            "\nArguments\n"
            "1. newsize     (numeric, optional, default=100) The new keypool size\n"
            "\nExamples:\n"
            + HelpExampleCli("keypoolrefill", "")
            + HelpExampleRpc("keypoolrefill", "")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -keypool
    unsigned int kpSize = 0; // 0 表示通过 TopUpKeyPool() 基于 -keypool 选项的默认密钥池大小
    if (params.size() > 0) {
        if (params[0].get_int() < 0) // 密钥池大小不能小于 0
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)params[0].get_int(); // 获取密钥池大小
    }

    EnsureWalletIsUnlocked(); // 确保钱包当前未加密
    pwalletMain->TopUpKeyPool(kpSize); // 根据指定大小填充密钥池

    if (pwalletMain->GetKeyPoolSize() < kpSize) // 填充后的密钥池大小不能小于 kpSize
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");

    return NullUniValue; // 返回空值
}


static void LockWallet(CWallet* pWallet)
{
    LOCK(cs_nWalletUnlockTime);
    nWalletUnlockTime = 0;
    pWallet->Lock();
}

UniValue walletpassphrase(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保钱包可用
        return NullUniValue;
    
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2)) // 参数个数必须为 2 个
        throw runtime_error( // 命令帮助反馈
            "walletpassphrase \"passphrase\" timeout\n"
            "\nStores the wallet decryption key in memory for 'timeout' seconds.\n"
            "This is needed prior to performing transactions related to private keys such as sending bitcoins\n"
            "\nArguments:\n"
            "1. \"passphrase\"     (string, required) The wallet passphrase\n"
            "2. timeout            (numeric, required) The time to keep the decryption key in seconds.\n"
            "\nNote:\n"
            "Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock\n"
            "time that overrides the old one.\n"
            "\nExamples:\n"
            "\nunlock the wallet for 60 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 60") +
            "\nLock the wallet again (before 60 seconds)\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("walletpassphrase", "\"my pass phrase\", 60")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    if (fHelp) // 钱包未加密时无法查看该命令帮助
        return true;
    if (!pwalletMain->IsCrypted()) // 钱包未加密时无法执行该命令
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");

    // Note that the walletpassphrase is stored in params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100); // 预开辟 100 个字节的空间
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    strWalletPass = params[0].get_str().c_str(); // 获取用户指定的钱包密码

    if (strWalletPass.length() > 0) // 密码长度必须大于 0
    {
        if (!pwalletMain->Unlock(strWalletPass)) // 解锁钱包
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }
    else
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    pwalletMain->TopUpKeyPool(); // 充满密钥池

    int64_t nSleepTime = params[1].get_int64(); // 获取密钥过期时间作为睡眠时间
    LOCK(cs_nWalletUnlockTime);
    nWalletUnlockTime = GetTime() + nSleepTime; // 得出绝对秒数
    RPCRunLater("lockwallet", boost::bind(LockWallet, pwalletMain), nSleepTime); // 稍后运行锁定钱包函数

    return NullUniValue;
}


UniValue walletpassphrasechange(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保钱包当前可用
        return NullUniValue;
    
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2)) // 钱包已加密 且 参数必须为 2 个
        throw runtime_error( // 命令帮助反馈
            "walletpassphrasechange \"oldpassphrase\" \"newpassphrase\"\n"
            "\nChanges the wallet passphrase from 'oldpassphrase' to 'newpassphrase'.\n"
            "\nArguments:\n"
            "1. \"oldpassphrase\"      (string) The current passphrase\n"
            "2. \"newpassphrase\"      (string) The new passphrase\n"
            "\nExamples:\n"
            + HelpExampleCli("walletpassphrasechange", "\"old one\" \"new one\"")
            + HelpExampleRpc("walletpassphrasechange", "\"old one\", \"new one\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    if (fHelp) // 若钱包未加密，则无法显示该命令帮助
        return true;
    if (!pwalletMain->IsCrypted()) // 若钱包未加密，则无法使用该命令
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = params[0].get_str().c_str(); // 获取用户指定的旧密码

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = params[1].get_str().c_str(); // 获取用户指定的新密码

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1) // 新旧密码长度都不能小于 1
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass)) // 改变钱包密码
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    return NullUniValue; // 返回空值
}


UniValue walletlock(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保钱包当前可用
        return NullUniValue;
    
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 0)) // 钱包已加密 且 没有参数
        throw runtime_error( // 命令帮助反馈
            "walletlock\n"
            "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.\n"
            "\nExamples:\n"
            "\nSet the passphrase for 2 minutes to perform a transaction\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 120") +
            "\nPerform a send (requires passphrase set)\n"
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 1.0") +
            "\nClear the passphrase since we are done before 2 minutes is up\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("walletlock", "")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    if (fHelp) // 钱包未加密时无法查看该命令帮助
        return true;
    if (!pwalletMain->IsCrypted()) // 钱包未加密时无法使用该命令
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");

    {
        LOCK(cs_nWalletUnlockTime);
        pwalletMain->Lock(); // 锁定钱包
        nWalletUnlockTime = 0; // 钱包解锁过期时间置 0
    }

    return NullUniValue; // 返回空值
}


UniValue encryptwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保钱包当前可用
        return NullUniValue;
    
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() != 1)) // 钱包未加密 且 参数只能有 1 个
        throw runtime_error( // 命令参数反馈
            "encryptwallet \"passphrase\"\n"
            "\nEncrypts the wallet with 'passphrase'. This is for first time encryption.\n"
            "After this, any calls that interact with private keys such as sending or signing \n"
            "will require the passphrase to be set prior the making these calls.\n"
            "Use the walletpassphrase call for this, and then walletlock call.\n"
            "If the wallet is already encrypted, use the walletpassphrasechange call.\n"
            "Note that this will shutdown the server.\n"
            "\nArguments:\n"
            "1. \"passphrase\"    (string) The pass phrase to encrypt the wallet with. It must be at least 1 character, but should be long.\n"
            "\nExamples:\n"
            "\nEncrypt you wallet\n"
            + HelpExampleCli("encryptwallet", "\"my pass phrase\"") +
            "\nNow set the passphrase to use the wallet, such as for signing or sending bitcoin\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\"") +
            "\nNow we can so something like sign\n"
            + HelpExampleCli("signmessage", "\"bitcoinaddress\" \"test message\"") +
            "\nNow lock the wallet again by removing the passphrase\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("encryptwallet", "\"my pass phrase\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    if (fHelp) // 钱包加密时帮助处理，不反馈任何信息
        return true;
    if (pwalletMain->IsCrypted()) // 若钱包已加密
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strWalletPass; // 创建一个安全字符串对象，用来保存密码
    strWalletPass.reserve(100); // 预开辟 100 个字符的空间
    strWalletPass = params[0].get_str().c_str(); // 获取用户指定的密码

    if (strWalletPass.length() < 1) // 密码长度不能小于 1，至少为 1 个字符
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwalletMain->EncryptWallet(strWalletPass)) // 加密钱包
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

    // BDB seems to have a bad habit of writing old data into // Berkeley DB 似乎有一个坏习惯，
    // slack space in .dat files; that is bad if the old data is // 把旧数据写入 .dat 文件的松散空
    // unencrypted private keys. So: // 糟糕的是旧数据是没有加密的私钥，所以：
    StartShutdown(); // 关闭核心服务器
    return "wallet encrypted; Bitcoin server stopping, restart to run with encrypted wallet. The keypool has been flushed, you need to make a new backup."; // 返回该信息表示加密成功
}

UniValue lockunspent(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 2) // 参数只能是 1 个或 2 个
        throw runtime_error( // 命令帮助反馈
            "lockunspent unlock [{\"txid\":\"txid\",\"vout\":n},...]\n"
            "\nUpdates list of temporarily unspendable outputs.\n"
            "Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.\n"
            "A locked transaction output will not be chosen by automatic coin selection, when spending bitcoins.\n"
            "Locks are stored in memory only. Nodes start with zero locked outputs, and the locked output list\n"
            "is always cleared (by virtue of process exit) when a node stops or fails.\n"
            "Also see the listunspent call\n"
            "\nArguments:\n"
            "1. unlock            (boolean, required) Whether to unlock (true) or lock (false) the specified transactions\n"
            "2. \"transactions\"  (string, required) A json array of objects. Each object the txid (string) vout (numeric)\n"
            "     [           (json array of json objects)\n"
            "       {\n"
            "         \"txid\":\"id\",    (string) The transaction id\n"
            "         \"vout\": n         (numeric) The output number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "true|false    (boolean) Whether the command was successful or not\n"

            "\nExamples:\n"
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("lockunspent", "false, \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    if (params.size() == 1) // 若只有一个参数
        RPCTypeCheck(params, boost::assign::list_of(UniValue::VBOOL)); // 验证参数类型
    else
        RPCTypeCheck(params, boost::assign::list_of(UniValue::VBOOL)(UniValue::VARR));

    bool fUnlock = params[0].get_bool(); // 获取加解锁的状态

    if (params.size() == 1) { // 若只有一个参数
        if (fUnlock) // 若是解锁
            pwalletMain->UnlockAllCoins(); // 解锁全部
        return true;
    }

    UniValue outputs = params[1].get_array(); // 获取交易输出索引数组
    for (unsigned int idx = 0; idx < outputs.size(); idx++) { // 遍历该数组
        const UniValue& output = outputs[idx]; // 获取一个对象（交易输出索引）
        if (!output.isObject())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected object");
        const UniValue& o = output.get_obj(); // 获取该对象

        RPCTypeCheckObj(o, boost::assign::map_list_of("txid", UniValue::VSTR)("vout", UniValue::VNUM)); // 检查对象类型，"交易索引" 为字符串，"交易输出索引" 为数字型

        string txid = find_value(o, "txid").get_str(); // 获取交易索引
        if (!IsHex(txid)) // 判断是否为 16 进制
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");

        int nOutput = find_value(o, "vout").get_int(); // 获取交易输出索引
        if (nOutput < 0) // 该值大于等于 0
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        COutPoint outpt(uint256S(txid), nOutput); // 构建一个输出点对象

        if (fUnlock) // 若解锁
            pwalletMain->UnlockCoin(outpt); // 解锁该交易输出
        else // 加锁
            pwalletMain->LockCoin(outpt); // 加锁该交易输出
    }

    return true; // 成功返回 true
}

UniValue listlockunspent(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() > 0) // 没有参数
        throw runtime_error( // 命令帮助反馈
            "listlockunspent\n"
            "\nReturns list of temporarily unspendable outputs.\n"
            "See the lockunspent call to lock and unlock transactions for spending.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"txid\" : \"transactionid\",     (string) The transaction id locked\n"
            "    \"vout\" : n                      (numeric) The vout value\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("listlockunspent", "")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    vector<COutPoint> vOutpts; // 创建输出点列表
    pwalletMain->ListLockedCoins(vOutpts); // 获取锁定的交易输出集合

    UniValue ret(UniValue::VARR); // 创建数组类型的结果集

    BOOST_FOREACH(COutPoint &outpt, vOutpts) { // 遍历输出点列表
        UniValue o(UniValue::VOBJ);

        o.push_back(Pair("txid", outpt.hash.GetHex())); // 获取输出点的交易索引
        o.push_back(Pair("vout", (int)outpt.n)); // 获取输出点的输出索引
        ret.push_back(o); // 加入结果集
    }

    return ret; // 返回结果集
}

UniValue settxfee(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 1) // 参数必须为 1 个
        throw runtime_error( // 命令帮助反馈
            "settxfee amount\n"
            "\nSet the transaction fee per kB. Overwrites the paytxfee parameter.\n"
            "\nArguments:\n"
            "1. amount         (numeric or sting, required) The transaction fee in " + CURRENCY_UNIT + "/kB\n"
            "\nResult\n"
            "true|false        (boolean) Returns true if successful\n"
            "\nExamples:\n"
            + HelpExampleCli("settxfee", "0.00001")
            + HelpExampleRpc("settxfee", "0.00001")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    // Amount
    CAmount nAmount = AmountFromValue(params[0]); // 获取指定交易费，包含范围检查

    payTxFee = CFeeRate(nAmount, 1000); // 设置交易费
    return true; // 设置成功返回 true
}

UniValue getwalletinfo(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保钱包当前可用
        return NullUniValue;
    
    if (fHelp || params.size() != 0) // 没有参数
        throw runtime_error( // 命令帮助反馈
            "getwalletinfo\n"
            "Returns an object containing various wallet state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"walletversion\": xxxxx,     (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,         (numeric) the total confirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"unconfirmed_balance\": xxx, (numeric) the total unconfirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"immature_balance\": xxxxxx, (numeric) the total immature balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"txcount\": xxxxxxx,         (numeric) the total number of transactions in the wallet\n"
            "  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,         (numeric) the transaction fee configuration, set in " + CURRENCY_UNIT + "/kB\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getwalletinfo", "")
            + HelpExampleRpc("getwalletinfo", "")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    UniValue obj(UniValue::VOBJ); // 创建目标类型对象
    obj.push_back(Pair("walletversion", pwalletMain->GetVersion())); // 钱包版本
    obj.push_back(Pair("balance",       ValueFromAmount(pwalletMain->GetBalance()))); // 钱包余额（可用，已确认，已成熟）
    obj.push_back(Pair("unconfirmed_balance", ValueFromAmount(pwalletMain->GetUnconfirmedBalance()))); // 未确认余额
    obj.push_back(Pair("immature_balance",    ValueFromAmount(pwalletMain->GetImmatureBalance()))); // 未成熟余额
    obj.push_back(Pair("txcount",       (int)pwalletMain->mapWallet.size())); // 该钱包内的交易数
    obj.push_back(Pair("keypoololdest", pwalletMain->GetOldestKeyPoolTime())); // 密钥池最早的密钥创建时间
    obj.push_back(Pair("keypoolsize",   (int)pwalletMain->GetKeyPoolSize())); // 密钥池大小
    if (pwalletMain->IsCrypted()) // 若钱包已加密
        obj.push_back(Pair("unlocked_until", nWalletUnlockTime)); // 解锁过期时间
    obj.push_back(Pair("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK()))); // 交易费
    return obj; // 返回结果
}

UniValue resendwallettransactions(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "resendwallettransactions\n"
            "Immediately re-broadcast unconfirmed wallet transactions to all peers.\n"
            "Intended only for testing; the wallet code periodically re-broadcasts\n"
            "automatically.\n"
            "Returns array of transaction ids that were re-broadcast.\n"
            );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    std::vector<uint256> txids = pwalletMain->ResendWalletTransactionsBefore(GetTime());
    UniValue result(UniValue::VARR);
    BOOST_FOREACH(const uint256& txid, txids)
    {
        result.push_back(txid.ToString());
    }
    return result;
}

UniValue listunspent(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() > 3) // 参数最多 3 个
        throw runtime_error( // 命令帮助反馈
            "listunspent ( minconf maxconf  [\"address\",...] )\n"
            "\nReturns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
            "Optionally filter to only include txouts paid to specified addresses.\n"
            "Results are an array of Objects, each of which has:\n"
            "{txid, vout, scriptPubKey, amount, confirmations}\n"
            "\nArguments:\n"
            "1. minconf          (numeric, optional, default=1) The minimum confirmations to filter\n"
            "2. maxconf          (numeric, optional, default=9999999) The maximum confirmations to filter\n"
            "3. \"addresses\"    (string) A json array of bitcoin addresses to filter\n"
            "    [\n"
            "      \"address\"   (string) bitcoin address\n"
            "      ,...\n"
            "    ]\n"
            "\nResult\n"
            "[                   (array of json object)\n"
            "  {\n"
            "    \"txid\" : \"txid\",        (string) the transaction id \n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"address\" : \"address\",  (string) the bitcoin address\n"
            "    \"account\" : \"account\",  (string) DEPRECATED. The associated account, or \"\" for the default account\n"
            "    \"scriptPubKey\" : \"key\", (string) the script key\n"
            "    \"amount\" : x.xxx,         (numeric) the transaction amount in " + CURRENCY_UNIT + "\n"
            "    \"confirmations\" : n       (numeric) The number of confirmations\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples\n"
            + HelpExampleCli("listunspent", "")
            + HelpExampleCli("listunspent", "6 9999999 \"[\\\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\\\",\\\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\\\"]\"")
            + HelpExampleRpc("listunspent", "6, 9999999 \"[\\\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\\\",\\\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\\\"]\"")
        );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)(UniValue::VNUM)(UniValue::VARR)); // 检查参数类型

    int nMinDepth = 1; // 最小深度，默认为 1
    if (params.size() > 0)
        nMinDepth = params[0].get_int(); // 获取最小深度

    int nMaxDepth = 9999999; // 最大深度，默认为 9999999
    if (params.size() > 1)
        nMaxDepth = params[1].get_int(); // 获取最大深度

    set<CBitcoinAddress> setAddress; // 比特币地址集合
    if (params.size() > 2) { // 若指定了地址集
        UniValue inputs = params[2].get_array(); // 获取地址集
        for (unsigned int idx = 0; idx < inputs.size(); idx++) { // 遍历地址集
            const UniValue& input = inputs[idx]; // 获取一个地址
            CBitcoinAddress address(input.get_str()); // 转换为字符串并包装为比特币地址对象
            if (!address.IsValid()) // 检查该地址有效性
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Bitcoin address: ")+input.get_str());
            if (setAddress.count(address)) // 保证集合里没有该地址
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+input.get_str());
           setAddress.insert(address); // 插入地址集合
        }
    }

    UniValue results(UniValue::VARR); // 创建数组类型的结果集
    vector<COutput> vecOutputs; // 输出列表
    assert(pwalletMain != NULL); // 钱包可用
    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁
    pwalletMain->AvailableCoins(vecOutputs, false, NULL, true); // 获取可花费的输出列表
    BOOST_FOREACH(const COutput& out, vecOutputs) { // 遍历该列表
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth) // 深度（确认数）在指定范围内
            continue;

        if (setAddress.size()) { // 若地址集大小大于 0
            CTxDestination address;
            if (!ExtractDestination(out.tx->vout[out.i].scriptPubKey, address)) // 根据输出脚本提取地址
                continue;

            if (!setAddress.count(address)) // 查看地址集中是否含此地址
                continue;
        } // 多余？

        CAmount nValue = out.tx->vout[out.i].nValue; // 获取输出金额
        const CScript& pk = out.tx->vout[out.i].scriptPubKey; // 获取公钥脚本
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex())); // 交易索引（16 进制形式）
        entry.push_back(Pair("vout", out.i)); // 交易输出索引
        CTxDestination address;
        if (ExtractDestination(out.tx->vout[out.i].scriptPubKey, address)) { // 根据交易输出脚本获取交易地址
            entry.push_back(Pair("address", CBitcoinAddress(address).ToString())); // 交易输出的公钥地址
            if (pwalletMain->mapAddressBook.count(address)) // 若在地址簿中查到该地址
                entry.push_back(Pair("account", pwalletMain->mapAddressBook[address].name)); // 获取帐户名
        }
        entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end()))); // 公钥脚本
        if (pk.IsPayToScriptHash()) { // 是否支付到脚本哈希
            CTxDestination address;
            if (ExtractDestination(pk, address)) {
                const CScriptID& hash = boost::get<CScriptID>(address); // 通过地址获取脚本索引
                CScript redeemScript;
                if (pwalletMain->GetCScript(hash, redeemScript)) // 通过索引获取赎回脚本
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }
        entry.push_back(Pair("amount",ValueFromAmount(nValue))); // 可用余额
        entry.push_back(Pair("confirmations",out.nDepth)); // 确认数（深度）
        entry.push_back(Pair("spendable", out.fSpendable)); // 是否可花费
        results.push_back(entry); // 加入结果集
    }

    return results; // 返回结果集
}

UniValue fundrawtransaction(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2) // 参数为 1 或 2 个
        throw runtime_error( // 命令帮助反馈
                            "fundrawtransaction \"hexstring\" includeWatching\n"
                            "\nAdd inputs to a transaction until it has enough in value to meet its out value.\n"
                            "This will not modify existing inputs, and will add one change output to the outputs.\n"
                            "Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.\n"
                            "The inputs added will not be signed, use signrawtransaction for that.\n"
                            "Note that all existing inputs must have their previous output transaction be in the wallet.\n"
                            "Note that all inputs selected must be of standard form and P2SH scripts must be"
                            "in the wallet using importaddress or addmultisigaddress (to calculate fees).\n"
                            "Only pay-to-pubkey, multisig, and P2SH versions thereof are currently supported for watch-only\n"
                            "\nArguments:\n"
                            "1. \"hexstring\"     (string, required) The hex string of the raw transaction\n"
                            "2. includeWatching (boolean, optional, default false) Also select inputs which are watch only\n"
                            "\nResult:\n"
                            "{\n"
                            "  \"hex\":       \"value\", (string)  The resulting raw transaction (hex-encoded string)\n"
                            "  \"fee\":       n,         (numeric) Fee the resulting transaction pays\n"
                            "  \"changepos\": n          (numeric) The position of the added change output, or -1\n"
                            "}\n"
                            "\"hex\"             \n"
                            "\nExamples:\n"
                            "\nCreate a transaction with no inputs\n"
                            + HelpExampleCli("createrawtransaction", "\"[]\" \"{\\\"myaddress\\\":0.01}\"") +
                            "\nAdd sufficient unsigned inputs to meet the output value\n"
                            + HelpExampleCli("fundrawtransaction", "\"rawtransactionhex\"") +
                            "\nSign the transaction\n"
                            + HelpExampleCli("signrawtransaction", "\"fundedtransactionhex\"") +
                            "\nSend the transaction\n"
                            + HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\"")
                            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VBOOL)); // 检查参数类型

    // parse hex string from parameter
    CTransaction origTx; // 原始交易
    if (!DecodeHexTx(origTx, params[0].get_str())) // 从参数解析 16 进制字符串
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    if (origTx.vout.size() == 0) // 交易的输出列表不能为空
        throw JSONRPCError(RPC_INVALID_PARAMETER, "TX must have at least one output");

    bool includeWatching = false; // 是否包含 watch-only 地址，默认不包含
    if (params.size() > 1)
        includeWatching = params[1].get_bool(); // 获取用户设置

    CMutableTransaction tx(origTx); // 构建一笔可变版本的交易
    CAmount nFee; // 交易费
    string strFailReason;
    int nChangePos = -1; // 改变位置
    if(!pwalletMain->FundTransaction(tx, nFee, nChangePos, strFailReason, includeWatching)) // 资助交易，增加输入和找零输出（如果有的话）
        throw JSONRPCError(RPC_INTERNAL_ERROR, strFailReason);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeHexTx(tx))); // 16 进制编码交易
    result.push_back(Pair("changepos", nChangePos)); // 改变位置
    result.push_back(Pair("fee", ValueFromAmount(nFee))); // 交易费

    return result; // 返回结果集
}
