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

bool EnsureWalletIsAvailable(bool avoidException) // ��鵱ǰǮ���Ƿ����
{
    if (!pwalletMain) // ��Ǯ��δ����
    {
        if (!avoidException)
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (disabled)");
        else
            return false;
    }
    return true; // Ǯ��������ֱ�ӷ��� true
}

void EnsureWalletIsUnlocked()
{
    if (pwalletMain->IsLocked()) // ��Ǯ������
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first."); // �׳�������Ϣ
}

void WalletTxToJSON(const CWalletTx& wtx, UniValue& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry.push_back(Pair("confirmations", confirms)); // ȷ����
    if (wtx.IsCoinBase())
        entry.push_back(Pair("generated", true)); // Ϊ���ҽ���
    if (confirms > 0) // ������
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex())); // �����ϣ
        entry.push_back(Pair("blockindex", wtx.nIndex)); // ��������
        entry.push_back(Pair("blocktime", mapBlockIndex[wtx.hashBlock]->GetBlockTime())); // ���鴴��ʱ��
    } else { // �����ڴ���У�δ������
        entry.push_back(Pair("trusted", wtx.IsTrusted())); // �ý��׿���
    }
    uint256 hash = wtx.GetHash();
    entry.push_back(Pair("txid", hash.GetHex())); // ��������
    UniValue conflicts(UniValue::VARR);
    BOOST_FOREACH(const uint256& conflict, wtx.GetConflicts())
        conflicts.push_back(conflict.GetHex());
    entry.push_back(Pair("walletconflicts", conflicts)); // Ǯ����ͻ
    entry.push_back(Pair("time", wtx.GetTxTime())); // ���׷���ʱ��
    entry.push_back(Pair("timereceived", (int64_t)wtx.nTimeReceived)); // ���׽���ʱ��

    // Add opt-in RBF status // ���ѡ���Ե� RBF ״̬
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

string AccountFromValue(const UniValue& value) // �Ӳ����л�ȡ�˻���
{
    string strAccount = value.get_str(); // �� UniValue ���͵Ĳ���ת��Ϊ std::string ����
    if (strAccount == "*") // �˻�������Ϊ "*"
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount; // ���ػ�ȡ���˻���������Ϊ��
}

UniValue getnewaddress(const UniValue& params, bool fHelp) // ��ָ���˻����½�һ����ַ������ָ���˻���Ĭ����ӵ�""���˻���
{
    if (!EnsureWalletIsAvailable(fHelp)) // 1.ȷ��Ǯ�����ã���Ǯ���Ѵ����ɹ�
        return NullUniValue;
    
    if (fHelp || params.size() > 1) // ��������Ϊ 0 �� 1����Ҫôʹ��Ĭ���˻���Ҫôָ���˻�
        throw runtime_error( // 2.�鿴������İ�������������������� 1 �������ظ�����İ���
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // 3.��Ǯ������

    // Parse the account first so we don't generate a key if there's an error
    string strAccount; // ���ڱ����ʻ���
    if (params.size() > 0) // �� 1 �����������
        strAccount = AccountFromValue(params[0]); // 4.������һ��������������Ϊ�˻���

    if (!pwalletMain->IsLocked()) // ���Ǯ���Ƿ����������û����ܣ�
        pwalletMain->TopUpKeyPool(); // 5.�����Կ��

    // Generate a new key that is added to wallet
    CPubKey newKey; // 6.����һ������Կ����ӵ�Ǯ��������һ����Ӧ�ı��رҵ�ַ
    if (!pwalletMain->GetKeyFromPool(newKey)) // ��ȡһ����Կ
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID(); // �� 65 bytes �Ĺ�Կ���� hash160(���� sha256, �� ripemd160)

    pwalletMain->SetAddressBook(keyID, strAccount, "receive");

    return CBitcoinAddress(keyID).ToString(); // 160 λ�Ĺ�Կת��Ϊ��Կ��ַ��Base58(1 + 20 + 4 bytes)
}


CBitcoinAddress GetAccountAddress(string strAccount, bool bForceNew=false)
{
    CWalletDB walletdb(pwalletMain->strWalletFile); // ����Ǯ�����ݿ����

    CAccount account;
    walletdb.ReadAccount(strAccount, account); // �����ݿ��л�ȡָ���˻�������

    bool bKeyUsed = false; // ����Կ�Ƿ�����ʹ�ñ�־

    // Check if the current key has been used
    if (account.vchPubKey.IsValid()) // ���ù�Կ��Ч
    {
        CScript scriptPubKey = GetScriptForDestination(account.vchPubKey.GetID());
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin();
             it != pwalletMain->mapWallet.end() && account.vchPubKey.IsValid();
             ++it)
        {
            const CWalletTx& wtx = (*it).second;
            BOOST_FOREACH(const CTxOut& txout, wtx.vout) // �������������
                if (txout.scriptPubKey == scriptPubKey) // ����Կ�ű�һ��
                    bKeyUsed = true; // ��־��Ϊ true
        }
    }

    // Generate a new key
    if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed) // ��Чʱ��������Կ
    {
        if (!pwalletMain->GetKeyFromPool(account.vchPubKey)) // ����Կ���л�ȡһ����Կ�Ĺ�Կ
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

        pwalletMain->SetAddressBook(account.vchPubKey.GetID(), strAccount, "receive"); // ���õ�ַ��
        walletdb.WriteAccount(strAccount, account); // �Ѹ��˻�д��Ǯ�����ݿ���
    }

    return CBitcoinAddress(account.vchPubKey.GetID()); // ��ȡ��Կ��Ӧ������������
}

UniValue getaccountaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = AccountFromValue(params[0]); // ���Ƚ����˻����������������ǲ�������һ����Կ

    UniValue ret(UniValue::VSTR);

    ret = GetAccountAddress(strAccount).ToString(); // ��ȡָ���˻����տ��ַ
    return ret; // ����һ�����رҵ�ַ
}


UniValue getrawchangeaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() > 1) // û�в������������
        throw runtime_error( // �����������
            "getrawchangeaddress\n"
            "\nReturns a new Bitcoin address, for receiving change.\n"
            "This is for use with raw transactions, NOT normal use.\n"
            "\nResult:\n"
            "\"address\"    (string) The address\n"
            "\nExamples:\n"
            + HelpExampleCli("getrawchangeaddress", "")
            + HelpExampleRpc("getrawchangeaddress", "")
       );

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    if (!pwalletMain->IsLocked()) // ����ǰǮ������δ����״̬
        pwalletMain->TopUpKeyPool(); // �����Կ��

    CReserveKey reservekey(pwalletMain); // ����һ����Կ����Ŀ
    CPubKey vchPubKey;
    if (!reservekey.GetReservedKey(vchPubKey)) // ��ȡһ����Կ���е���Կ�Ĺ�Կ
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    reservekey.KeepKey(); // ����Կ�����Ƴ���ȡ����Կ���������Կ����Ŀ��Ϣ

    CKeyID keyID = vchPubKey.GetID(); // ��ȡ��Կ����

    return CBitcoinAddress(keyID).ToString(); // Base58 �����ȡ��Կ��ַ������
}


UniValue setaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ��Ǯ����ǰ����
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 2) // ����Ϊ 1 �� 2 ��
        throw runtime_error( // �����������
            "setaccount \"bitcoinaddress\" \"account\"\n"
            "\nDEPRECATED. Sets the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"bitcoinaddress\"  (string, required) The bitcoin address to be associated with an account.\n"
            "2. \"account\"         (string, required) The account to assign the address to.\n"
            "\nExamples:\n"
            + HelpExampleCli("setaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"tabby\"")
            + HelpExampleRpc("setaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", \"tabby\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    CBitcoinAddress address(params[0].get_str()); // ��ȡָ���ı��رҵ�ַ
    if (!address.IsValid()) // ��֤��ַ�Ƿ���Ч
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");

    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]); // ��ȡָ�����˻�

    // Only add the account if the address is yours. // ����õ�ַ����ģ�ֻ������˻�
    if (IsMine(*pwalletMain, address.Get())) // ���õ�ַ���ҵ�
    {
        // Detect when changing the account of an address that is the 'unused current key' of another account: // ��⵽
        if (pwalletMain->mapAddressBook.count(address.Get())) // ���õ�ַ�ڵ�ַ����
        {
            string strOldAccount = pwalletMain->mapAddressBook[address.Get()].name; // ��ȡ��ַ�����ľ��˻���
            if (address == GetAccountAddress(strOldAccount)) // �����˻������ĵ�ַΪָ����ַ
                GetAccountAddress(strOldAccount, true); // ���ھ��˻�������һ���µ�ַ
        }
        pwalletMain->SetAddressBook(address.Get(), strAccount, "receive"); // �ٰѸõ�ַ������ָ���˻�
    }
    else
        throw JSONRPCError(RPC_MISC_ERROR, "setaccount can only be used with own address");

    return NullUniValue; // ���ؿ�ֵ
}


UniValue getaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    CBitcoinAddress address(params[0].get_str()); // ��ȡָ���ı��رҵ�ַ
    if (!address.IsValid()) // ����ַ�Ƿ���Ч
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");

    string strAccount; // �����˻���
    map<CTxDestination, CAddressBookData>::iterator mi = pwalletMain->mapAddressBook.find(address.Get()); // ��ȡ��ַ���ж�Ӧ��ַ����������
    if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.name.empty()) // �����ڸ��������˻����ǿ�
        strAccount = (*mi).second.name; // ��ȡ�˻���
    return strAccount; // ���������˻���
}


UniValue getaddressesbyaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    string strAccount = AccountFromValue(params[0]); // ��ȡָ���˻���

    // Find all addresses that have the given account // ���һ��ڸ����ʻ��������е�ַ
    UniValue ret(UniValue::VARR); // �����������͵Ľ������
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, CAddressBookData)& item, pwalletMain->mapAddressBook)
    { // ������ַ��
        const CBitcoinAddress& address = item.first; // ��ȡ���رҵ�ַ
        const string& strName = item.second.name; // ��ȡ�˻���
        if (strName == strAccount) // ����ָ���ʻ�����ͬ
            ret.push_back(address.ToString()); // �Ѹõ�ַ��������
    }
    return ret; // ���ؽ������
}

static void SendMoney(const CTxDestination &address, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew)
{
    CAmount curBalance = pwalletMain->GetBalance(); // 1.��ȡǮ�����

    // Check amount // ��鷢�͵Ľ��
    if (nValue <= 0) // �ý�����Ϊ����
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > curBalance) // Ҫ���͵Ľ��ܴ��ڵ�ǰǮ�����
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    // Parse Bitcoin address // �������رҵ�ַ
    CScript scriptPubKey = GetScriptForDestination(address); // 2.��Ŀ���ַ�л�ȡ�ű�

    // Create and send the transaction // ���������ͽ���
    CReserveKey reservekey(pwalletMain); // ��ʼ��һ����Կ����Կ����
    CAmount nFeeRequired; // ���轻�׷�
    std::string strError; // ������Ϣ
    vector<CRecipient> vecSend; // �����б�
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, fSubtractFeeFromAmount}; // ��ʼ��һ�������߶���
    vecSend.push_back(recipient); // ���뷢���б�
    if (!pwalletMain->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError)) { // ����һ�ʽ���
        if (!fSubtractFeeFromAmount && nValue + nFeeRequired > pwalletMain->GetBalance()) // �����ͽ��������׷ѣ����ͽ���뽻�׷ѵĺͲ��ܴ���Ǯ�����
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    if (!pwalletMain->CommitTransaction(wtxNew, reservekey)) // 3.�ύ����
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
}

UniValue sendtoaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 1.ȷ��Ǯ����ǰ����
        return NullUniValue;
    
    if (fHelp || params.size() < 2 || params.size() > 5) // 2.��������Ϊ 2 ��������Ϊ 5 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // 3.Ǯ������

    CBitcoinAddress address(params[0].get_str()); // 4.��ȡָ���ı��رҵ�ַ
    if (!address.IsValid()) // ��֤��ַ�Ƿ���Ч
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");

    // Amount // ���
    CAmount nAmount = AmountFromValue(params[1]); // ��ȡת�˽��
    if (nAmount <= 0) // ����С�ڵ��� 0
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    // Wallet comments // Ǯ����ע
    CWalletTx wtx; // һ��Ǯ�����׶���
    if (params.size() > 2 && !params[2].isNull() && !params[2].get_str().empty())
        wtx.mapValue["comment"] = params[2].get_str(); // ���ױ�ע
    if (params.size() > 3 && !params[3].isNull() && !params[3].get_str().empty())
        wtx.mapValue["to"]      = params[3].get_str(); // ���׵ĸ��˻���֯����ע

    bool fSubtractFeeFromAmount = false; // �۳����׷ѱ�־��Ĭ�Ϲر�
    if (params.size() > 4)
        fSubtractFeeFromAmount = params[4].get_bool(); // ��ȡ����

    EnsureWalletIsUnlocked(); // 5.ȷ����ǰǮ�����ڽ���״̬

    SendMoney(address.Get(), nAmount, fSubtractFeeFromAmount, wtx); // 6.���ͽ�ָ����ַ

    return wtx.GetHash().GetHex(); // 7.��ȡ���׹�ϣ��ת��Ϊ 16 ���Ʋ�����
}

UniValue listaddressgroupings(const UniValue& params, bool fHelp) // �г���ַ������Ϣ����ַ�����˻���
{
    if (!EnsureWalletIsAvailable(fHelp)) // 1.ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp) // 2.û�в���
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // 3.Ǯ������

    UniValue jsonGroupings(UniValue::VARR); // 4.��ַ���鼯�϶���
    map<CTxDestination, CAmount> balances = pwalletMain->GetAddressBalances(); // 4.1.��ȡ��ַ���ӳ���б�
    BOOST_FOREACH(set<CTxDestination> grouping, pwalletMain->GetAddressGroupings()) // 4.2.��ȡ��������ַ���鼯��
    {
        UniValue jsonGrouping(UniValue::VARR); // ��ַ�������
        BOOST_FOREACH(CTxDestination address, grouping) // ����һ����ַ����
        {
            UniValue addressInfo(UniValue::VARR); // һ����ַ��Ϣ����ַ�����˻���
            addressInfo.push_back(CBitcoinAddress(address).ToString()); // ��ȡ��ַ
            addressInfo.push_back(ValueFromAmount(balances[address])); // ��ȡ��ַ���
            {
                if (pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get()) != pwalletMain->mapAddressBook.end()) // ����ַ�����иõ�ַ
                    addressInfo.push_back(pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get())->second.name); // �Ѹõ�ַ�������˻��������ַ��Ϣ
            }
            jsonGrouping.push_back(addressInfo); // �����ַ����
        }
        jsonGroupings.push_back(jsonGrouping); // �����ַ���鼯��
    }
    return jsonGroupings; // ���ص�ַ���鼯��
}

UniValue signmessage(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() != 2) // ��������Ϊ 2 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    EnsureWalletIsUnlocked(); // ȷ����ǰǮ�����ڽ���״̬

    string strAddress = params[0].get_str(); // ��ȡָ����ַ
    string strMessage = params[1].get_str(); // ��ȡ��Ϣ

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid()) // ��֤��ַ�Ƿ���Ч
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID)) // ��ȡ��ַ��Ӧ����Կ����
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CKey key;
    if (!pwalletMain->GetKey(keyID, key)) // ͨ��������ȡ��Ӧ˽Կ
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");

    CHashWriter ss(SER_GETHASH, 0); // ��ϣд����������
    ss << strMessageMagic; // ������Ϣħ��ͷ
    ss << strMessage; // ������Ϣ

    vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig)) // ʹ��˽Կ����Ϣ����ǩ��������ȡǩ������
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size()); // base64 ����ǩ��������
}

UniValue getreceivedbyaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 2) // ����Ϊ 1 �� 2 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    // Bitcoin address
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str()); // ��ȡָ���ı��رҵ�ַ
    if (!address.IsValid()) // �жϸõ�ַ�Ƿ���Ч
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    CScript scriptPubKey = GetScriptForDestination(address.Get()); // ��ȡ��Կ�ű�
    if (!IsMine(*pwalletMain,scriptPubKey)) // ����Ƿ������Լ�
        return (double)0.0;

    // Minimum confirmations // ��Сȷ����
    int nMinDepth = 1; // ��С��ȣ�Ĭ��Ϊ 1
    if (params.size() > 1)
        nMinDepth = params[1].get_int(); // ��ȡָ����ȷ����

    // Tally // �ܼ�
    CAmount nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) // ����Ǯ������ӳ���б�
    {
        const CWalletTx& wtx = (*it).second; // ��ȡǮ������
        if (wtx.IsCoinBase() || !CheckFinalTx(wtx)) // ��Ϊ���ҽ��� �� �����һ�ʽ���
            continue; // ����

        BOOST_FOREACH(const CTxOut& txout, wtx.vout) // ������������б�
            if (txout.scriptPubKey == scriptPubKey) // ������ű�Ϊָ����ַ�Ĺ�Կ�ű�
                if (wtx.GetDepthInMainChain() >= nMinDepth) // �ҽ�����ȴ��ڵ�����С���
                    nAmount += txout.nValue; // �ۼӽ��׽��
    }

    return  ValueFromAmount(nAmount); // ����ֱ�Ӹ�ʽ�� Satoshi ����
}


UniValue getreceivedbyaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 2) // ����Ϊ 1 ���� 2 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    // Minimum confirmations // ��Сȷ����
    int nMinDepth = 1; // ��С��ȣ�Ĭ��Ϊ 1
    if (params.size() > 1)
        nMinDepth = params[1].get_int(); // ��ȡָ��ȷ������Ϊ��С���

    // Get the set of pub keys assigned to account // ��ȡָ���˻��Ĺ�Կ����
    string strAccount = AccountFromValue(params[0]); // ��ȡָ���˻�
    set<CTxDestination> setAddress = pwalletMain->GetAccountAddresses(strAccount); // ��ȡָ���˻��ĵ�ַ����

    // Tally // �ܼ�
    CAmount nAmount = 0; // int64_t
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) // ����Ǯ������ӳ���б�
    {
        const CWalletTx& wtx = (*it).second; // ��ȡǮ������
        if (wtx.IsCoinBase() || !CheckFinalTx(wtx)) // ��Ϊ���ҽ��� �� �����ս���
            continue; // ����

        BOOST_FOREACH(const CTxOut& txout, wtx.vout) // �����ý��׵�����б�
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*pwalletMain, address) && setAddress.count(address)) // ���������Կ�ű�����ȡ��ַ �� �õ�ַΪ�Լ��� �� ����ָ���˻���ַ��
                if (wtx.GetDepthInMainChain() >= nMinDepth) // �ҽ�����ȴ�����С���
                    nAmount += txout.nValue; // �ۼ�����Ľ��
        }
    }

    return (double)nAmount / (double)COIN; // ���㵥λ Satoshi Ϊ BTC
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
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() > 3) // �������Ϊ 3 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    if (params.size() == 0) // ���޲���
        return  ValueFromAmount(pwalletMain->GetBalance()); // ֱ�ӷ��ص�ǰ����Ǯ�������

    int nMinDepth = 1; // ��С��ȣ�Ĭ��Ϊ 1
    if (params.size() > 1)
        nMinDepth = params[1].get_int(); // ��ȡ��С���
    isminefilter filter = ISMINE_SPENDABLE; // ismine ������
    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY; // ��ȡ watchonly

    if (params[0].get_str() == "*") { // ��ָ���˻���Ϊ "*"
        // Calculate total balance a different way from GetBalance() // �Բ�ͬ�� GetBalance() �ķ�ʽ���������
        // (GetBalance() sums up all unspent TxOuts) // ��GetBalance() �ܼ�ȫ��δ���ѵ������
        // getbalance and "getbalance * 1 true" should return the same number // getbalance �� "getbalance * 1 true" Ӧ�÷�����ͬ������
        CAmount nBalance = 0;
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
        { // ����Ǯ������ӳ���б�
            const CWalletTx& wtx = (*it).second; // ��ȡǮ������
            if (!CheckFinalTx(wtx) || wtx.GetBlocksToMaturity() > 0 || wtx.GetDepthInMainChain() < 0) // ����Ƿ�Ϊ���ս��� �� δ���� �� ���������С�� 0
                continue; // ����

            CAmount allFee;
            string strSentAccount;
            list<COutputEntry> listReceived; // �����б�
            list<COutputEntry> listSent; // �����б�
            wtx.GetAmounts(listReceived, listSent, allFee, strSentAccount, filter); // ��ȡ��Ӧ�Ľ��
            if (wtx.GetDepthInMainChain() >= nMinDepth) // �ý��������ϵ���ȴ��ڵ�����С���
            {
                BOOST_FOREACH(const COutputEntry& r, listReceived) // ���������б�
                    nBalance += r.amount; // �ۼӽ��
            }
            BOOST_FOREACH(const COutputEntry& s, listSent) // ���������б�
                nBalance -= s.amount; // ��ȥ���ѵĽ��
            nBalance -= allFee; // ��ȥ���׷�
        }
        return  ValueFromAmount(nBalance); // �õ�Ǯ����������
    }

    string strAccount = AccountFromValue(params[0]); // ��ȡָ�����˻���

    CAmount nBalance = GetAccountBalance(strAccount, nMinDepth, filter); // ��ȡ�˻����

    return ValueFromAmount(nBalance); // �����˻����
}

UniValue getunconfirmedbalance(const UniValue &params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() > 0) // û�в���
        throw runtime_error( // �����������
                "getunconfirmedbalance\n"
                "Returns the server's total unconfirmed balance\n");

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    return ValueFromAmount(pwalletMain->GetUnconfirmedBalance()); // ��ȡδȷ�ϵ�������
}


UniValue movecmd(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() < 3 || params.size() > 5) // �������� 3 �������� 5 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    string strFrom = AccountFromValue(params[0]); // ��ʼ�˻�
    string strTo = AccountFromValue(params[1]); // Ŀ���˻�
    CAmount nAmount = AmountFromValue(params[2]); // ת�˽��
    if (nAmount <= 0) // ת�˽���С�� 0
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    if (params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int(); // δʹ�õĲ�������������С��ȣ�Ŀǰ�������ͼ��
    string strComment;
    if (params.size() > 4)
        strComment = params[4].get_str(); // ��ȡ��ע

    CWalletDB walletdb(pwalletMain->strWalletFile); // ����Ǯ�����ݿ����
    if (!walletdb.TxnBegin()) // ���ݿ��ʼ�����
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    int64_t nNow = GetAdjustedTime(); // ��ȡ��ǰʱ��

    // Debit // ���
    CAccountingEntry debit; // �����˻���Ŀ�������ڲ�ת�ˣ��������
    debit.nOrderPos = pwalletMain->IncOrderPosNext(&walletdb); // ������һ�����׵����
    debit.strAccount = strFrom; // ����˻�
    debit.nCreditDebit = -nAmount; // �����Ϊ��������ʾ���
    debit.nTime = nNow; // ��¼���ʱ��
    debit.strOtherAccount = strTo; // ��ǽ����Ŀ���˻�
    debit.strComment = strComment; // ��¼��ע��Ϣ
    pwalletMain->AddAccountingEntry(debit, walletdb); // �Ѹ��˻���Ŀ����Ǯ�����ݿ�

    // Credit // ����
    CAccountingEntry credit; //  �����˻���Ŀ�������ڲ�ת�ˣ��������
    credit.nOrderPos = pwalletMain->IncOrderPosNext(&walletdb); // ������һ�����׵����
    credit.strAccount = strTo; // �����˻�
    credit.nCreditDebit = nAmount; // �����Ϊ��������ʾ����
    credit.nTime = nNow; // ��¼����ʱ��
    credit.strOtherAccount = strFrom; // ��Ǵ������ʼ�˻�
    credit.strComment = strComment; // ��¼��ע��Ϣ
    pwalletMain->AddAccountingEntry(credit, walletdb); // �Ѹ��˻���Ŀ����Ǯ�����ݿ�

    if (!walletdb.TxnCommit()) // Ǯ�����ݿ⽻���ύ
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    return true; // �ɹ����� true
}


UniValue sendfrom(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() < 3 || params.size() > 6) // ��������Ϊ 3 ��������Ϊ 6 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    string strAccount = AccountFromValue(params[0]); // ��ȡָ���˻�
    CBitcoinAddress address(params[1].get_str()); // ��ȡĿ����رҵ�ַ
    if (!address.IsValid()) // ��֤��ַ�Ƿ���Ч
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    CAmount nAmount = AmountFromValue(params[2]); // ��ȡ���ͽ��
    if (nAmount <= 0) // �ý�������� 0
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    int nMinDepth = 1; // ��С��ȣ�ȷ������
    if (params.size() > 3)
        nMinDepth = params[3].get_int(); // ��ȡ��Сȷ����

    CWalletTx wtx; // ����Ǯ������
    wtx.strFromAccount = strAccount; // ��ʼ�������˻�
    if (params.size() > 4 && !params[4].isNull() && !params[4].get_str().empty())
        wtx.mapValue["comment"] = params[4].get_str(); // ���ױ�ע
    if (params.size() > 5 && !params[5].isNull() && !params[5].get_str().empty())
        wtx.mapValue["to"]      = params[5].get_str(); // �����˻���֯��ע

    EnsureWalletIsUnlocked(); // ȷ����ǰǮ������Ϊ����״̬

    // Check funds // ����ʽ�
    CAmount nBalance = GetAccountBalance(strAccount, nMinDepth, ISMINE_SPENDABLE); // ��ȡָ���˻����
    if (nAmount > nBalance) // ���ͽ��ܴ��ڸ��˻����
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    SendMoney(address.Get(), nAmount, false, wtx); // ���ͽ��

    return wtx.GetHash().GetHex(); // ��ȡ���׹�ϣ��ת��Ϊ 16 ���Ʋ�����
}


UniValue sendmany(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() < 2 || params.size() > 5) // ��������Ϊ 2 ��������Ϊ 5 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    string strAccount = AccountFromValue(params[0]); // ��ȡָ���˻�
    UniValue sendTo = params[1].get_obj(); // ��ȡ���Ͷ��󣨵�ַ�ͽ�
    int nMinDepth = 1; // ��С��ȣ�Ĭ��Ϊ 1
    if (params.size() > 2)
        nMinDepth = params[2].get_int(); // ��ȡ��Сȷ����

    CWalletTx wtx; // ����һ��Ǯ������
    wtx.strFromAccount = strAccount; // ��ʼ�������˻�
    if (params.size() > 3 && !params[3].isNull() && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str(); // ��ȡ���ױ�ע

    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (params.size() > 4)
        subtractFeeFromAmount = params[4].get_array(); // ��ȡ�������͵Ĵӽ���м�ȥ���׷�

    set<CBitcoinAddress> setAddress; // ���رҵ�ַ��
    vector<CRecipient> vecSend; // �����б�

    CAmount totalAmount = 0; // Ҫ���͵��ܽ��
    vector<string> keys = sendTo.getKeys(); // ��ȡĿ�ĵ�ַ�б�
    BOOST_FOREACH(const string& name_, keys) // ������ַ�б�
    {
        CBitcoinAddress address(name_); // ���رҵ�ַ����
        if (!address.IsValid()) // ��֤��ַ�Ƿ���Ч
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Bitcoin address: ")+name_);

        if (setAddress.count(address)) // ��ַ���в�Ӧ�ô��ڵ�ǰ��ַ����֤���͵��ĵ�ַ���ظ�
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address); // �����ַ��

        CScript scriptPubKey = GetScriptForDestination(address.Get()); // �ӵ�ַ��ȡ��Կ�ű�
        CAmount nAmount = AmountFromValue(sendTo[name_]); // ��ȡ�õ�ַ��Ӧ�Ľ��
        if (nAmount <= 0) // ��������� 0
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        totalAmount += nAmount; // �ۼӽ��

        bool fSubtractFeeFromAmount = false; // �Ƿ�ӽ���м�ȥ���׷ѱ�־����ʼ��Ϊ false
        for (unsigned int idx = 0; idx < subtractFeeFromAmount.size(); idx++) { // �����ö���
            const UniValue& addr = subtractFeeFromAmount[idx]; // ��ȡ��ַ
            if (addr.get_str() == name_) // ��Ϊָ����Ŀ�ĵ�ַ
                fSubtractFeeFromAmount = true; // ��־��Ϊ true
        }

        CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount}; // ��ʼ��һ�����ն���
        vecSend.push_back(recipient); // ���뷢���б�
    }

    EnsureWalletIsUnlocked(); // ȷ����ǰǮ�����ڽ���״̬

    // Check funds // ����ʽ�
    CAmount nBalance = GetAccountBalance(strAccount, nMinDepth, ISMINE_SPENDABLE); // ��ȡָ���˻����
    if (totalAmount > nBalance) // �����ܽ��ܴ����˻����
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send // ����
    CReserveKey keyChange(pwalletMain); // ����һ����Կ���е���Կ��Ŀ
    CAmount nFeeRequired = 0; // ���轻�׷�
    int nChangePosRet = -1;
    string strFailReason; // ���������Ϣ
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason); // ����һ�ʽ���
    if (!fCreated) // ��齻��״̬
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    if (!pwalletMain->CommitTransaction(wtx, keyChange)) // �ύ����
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

    return wtx.GetHash().GetHex(); // ��ȡ���׹�ϣ��ת��Ϊ 16 ���Ʋ�����
}

// Defined in rpcmisc.cpp
extern CScript _createmultisig_redeemScript(const UniValue& params);

UniValue addmultisigaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() < 2 || params.size() > 3) // ����Ϊ 2 �� 3 ��
    { // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]); // ��ȡָ���˻���

    // Construct using pay-to-script-hash: // ʹ�� P2SH ����
    CScript inner = _createmultisig_redeemScript(params); // ������ǩ��ؽű�
    CScriptID innerID(inner); // ��ȡ�ű�����
    pwalletMain->AddCScript(inner); // ��Ӹýű�������Ǯ��

    pwalletMain->SetAddressBook(innerID, strAccount, "send"); // ���õ�ַ��
    return CBitcoinAddress(innerID).ToString(); // �Խű��������� base58 ����󷵻�
}


struct tallyitem // ��Ŀ��
{
    CAmount nAmount; // ��Ĭ��Ϊ 0
    int nConf; // ȷ������Ĭ�� int �����ֵ
    vector<uint256> txids; // ���������б�
    bool fIsWatchonly; // ���� watchonly ��־��Ĭ�Ϲر�
    tallyitem() // �޲ι���
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
        fIsWatchonly = false;
    }
};

UniValue ListReceived(const UniValue& params, bool fByAccounts) // fByAccounts = true
{
    // Minimum confirmations // ���ȷ����
    int nMinDepth = 1; // ��С��ȣ�Ĭ��Ϊ 1
    if (params.size() > 0)
        nMinDepth = params[0].get_int(); // ��ȡ��С���

    // Whether to include empty accounts
    bool fIncludeEmpty = false; // �����������˻���־��Ĭ��Ϊ false
    if (params.size() > 1)
        fIncludeEmpty = params[1].get_bool(); // ��ȡ�Ƿ�����������˻���־

    isminefilter filter = ISMINE_SPENDABLE; // �ɻ���
    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY; // �����ڿ� watchonly

    // Tally // ����
    map<CBitcoinAddress, tallyitem> mapTally; // ��ַ��Ŀӳ���б�
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    { // ����Ǯ������ӳ���б�
        const CWalletTx& wtx = (*it).second; // ��ȡǮ������

        if (wtx.IsCoinBase() || !CheckFinalTx(wtx)) // �Ǵ��ҽ��� �� Ϊ���ս���
            continue;

        int nDepth = wtx.GetDepthInMainChain(); // ��ȡ�ý��׵������
        if (nDepth < nMinDepth) // ��Ȳ���С����С��ȣ����ȷ������
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        { // ������������б�
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address)) // ͨ�����������Կ�ű���ȡ��Կ��ַ
                continue;

            isminefilter mine = IsMine(*pwalletMain, address);
            if(!(mine & filter))
                continue;

            tallyitem& item = mapTally[address]; // ��ȡ��ַ��Ӧ����Ŀ
            item.nAmount += txout.nValue; // �ۼӽ���������
            item.nConf = min(item.nConf, nDepth); // ��ȡ�������
            item.txids.push_back(wtx.GetHash()); // ���뽻�������б�
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }
    }

    // Reply
    UniValue ret(UniValue::VARR); // �����������͵Ľ������
    map<string, tallyitem> mapAccountTally; // �˻���Ŀӳ���б�
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, CAddressBookData)& item, pwalletMain->mapAddressBook) // ������ַ��ӳ���б�
    {
        const CBitcoinAddress& address = item.first; // ��ȡ��ַ
        const string& strAccount = item.second.name; // ��ȡ�ʻ���
        map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address); // ��ȡ��ַ��Ӧ����Ŀ
        if (it == mapTally.end() && !fIncludeEmpty) // δ�ҵ� �� ����������˻���־Ϊ false
            continue; // ����

        CAmount nAmount = 0; // ���
        int nConf = std::numeric_limits<int>::max(); // ȷ������Ĭ�����ֵ
        bool fIsWatchonly = false; // watchonly ��־��Ĭ��Ϊ false
        if (it != mapTally.end()) // �ҵ�
        { // ��ַ��Ӧ��Ŀ
            nAmount = (*it).second.nAmount; // ��ȡ��ַ���
            nConf = (*it).second.nConf; // ��ȡ��ַȷ����
            fIsWatchonly = (*it).second.fIsWatchonly; // ��ȡ��ַ watchonly ��־
        }

        if (fByAccounts) // true
        {
            tallyitem& item = mapAccountTally[strAccount]; // ��ȡ�˻�����Ӧ����Ŀ
            item.nAmount += nAmount; // �ۼӽ��
            item.nConf = min(item.nConf, nConf); // ��ȡ��Сȷ����
            item.fIsWatchonly = fIsWatchonly; // ��ȡ watchonly ��־
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
        { // �����˻���Ŀӳ���б�
            CAmount nAmount = (*it).second.nAmount; // ��ȡ���
            int nConf = (*it).second.nConf; // ��ȡȷ����
            UniValue obj(UniValue::VOBJ); 
            if((*it).second.fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true)); // watchonly ��־
            obj.push_back(Pair("account",       (*it).first)); // �ʻ���
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount))); // ���
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf))); // ȷ����
            ret.push_back(obj); // ��������
        }
    }

    return ret; // ���ؽ������
}

UniValue listreceivedbyaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() > 3) // �������Ϊ 3 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    return ListReceived(params, false); // ��ȡ���ս���б�����
}

UniValue listreceivedbyaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() > 3) // �������Ϊ 3 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    return ListReceived(params, true); // �г��˻�������
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest)
{
    CBitcoinAddress addr;
    if (addr.Set(dest))
        entry.push_back(Pair("address", addr.ToString()));
}

void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, UniValue& ret, const isminefilter& filter)
{
    CAmount nFee; // ���׷�
    string strSentAccount; // �����˻�
    list<COutputEntry> listReceived; // ���������Ŀ�б�
    list<COutputEntry> listSent; // ���������Ŀ�б�

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter); // ��ȡ��Ӧ���

    bool fAllAccounts = (strAccount == string("*")); // ȫ���˻���־
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY); // watchonly ��־

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    { // �����б�ǿ� �� ���׷ѷ� 0 �� ȫ���˻� �� �����˻�Ϊָ���˻��������� "*" ��ʾȫ���˻���
        BOOST_FOREACH(const COutputEntry& s, listSent) // ���������б�
        {
            UniValue entry(UniValue::VOBJ);
            if(involvesWatchonly || (::IsMine(*pwalletMain, s.destination) & ISMINE_WATCH_ONLY))
                entry.push_back(Pair("involvesWatchonly", true));
            entry.push_back(Pair("account", strSentAccount)); // �����˻�
            MaybePushAddress(entry, s.destination); // ���͵�ַ
            entry.push_back(Pair("category", "send")); // �������Ϊ����
            entry.push_back(Pair("amount", ValueFromAmount(-s.amount))); // ���׽����ű�ʾ����
            if (pwalletMain->mapAddressBook.count(s.destination))
                entry.push_back(Pair("label", pwalletMain->mapAddressBook[s.destination].name)); // ��ǩΪ�ʻ���
            entry.push_back(Pair("vout", s.vout)); // �������
            entry.push_back(Pair("fee", ValueFromAmount(-nFee))); // ���׷�
            if (fLong) // true
                WalletTxToJSON(wtx, entry); // Ǯ��������Ϣת��Ϊ JSON ��ʽ
            entry.push_back(Pair("abandoned", wtx.isAbandoned())); // �Ƿ�����
            ret.push_back(entry); // ���뽻����Ϣ��
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    { // �����б�ǿ� �� �ý�����ȴ��ڵ�����С��ȣ�ȷ������
        BOOST_FOREACH(const COutputEntry& r, listReceived) // ���������б�
        {
            string account;
            if (pwalletMain->mapAddressBook.count(r.destination)) // ���õ�ַ�����ڵ�ַ��
                account = pwalletMain->mapAddressBook[r.destination].name; // ��ȡ��ַ��Ӧ�˻���
            if (fAllAccounts || (account == strAccount)) // ȫ���˻� �� ���˻�Ϊָ���˻���"*"��
            {
                UniValue entry(UniValue::VOBJ);
                if(involvesWatchonly || (::IsMine(*pwalletMain, r.destination) & ISMINE_WATCH_ONLY))
                    entry.push_back(Pair("involvesWatchonly", true));
                entry.push_back(Pair("account", account)); // �˻���
                MaybePushAddress(entry, r.destination); // ���յ�ַ
                if (wtx.IsCoinBase()) // �ý���Ϊ���ҽ���
                {
                    if (wtx.GetDepthInMainChain() < 1) // �ý����������ϵ����Ϊ 0
                        entry.push_back(Pair("category", "orphan")); // �¶���
                    else if (wtx.GetBlocksToMaturity() > 0) // ������������������ 0
                        entry.push_back(Pair("category", "immature")); // δ����
                    else
                        entry.push_back(Pair("category", "generate")); // regtest ����
                }
                else
                { // ��ͨ���ף��Ǵ��ҽ��ף�
                    entry.push_back(Pair("category", "receive")); // �������Ϊ����
                }
                entry.push_back(Pair("amount", ValueFromAmount(r.amount))); // ���׽��
                if (pwalletMain->mapAddressBook.count(r.destination)) // ���õ�ַ�����ڵ�ַ��
                    entry.push_back(Pair("label", account)); // ��ǩΪ�õ�ַ��Ӧ���ʻ���
                entry.push_back(Pair("vout", r.vout)); // �������
                if (fLong)
                    WalletTxToJSON(wtx, entry); // Ǯ��������Ϣת��Ϊ JSON
                ret.push_back(entry); // ���뽻����Ϣ��
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
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() > 4) // �������Ϊ 4 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    string strAccount = "*"; // �˻�����Ĭ��Ϊ "*" ��ʾȫ���˻�
    if (params.size() > 0)
        strAccount = params[0].get_str(); // ��ȡ�ʻ���
    int nCount = 10; // ��������Ĭ�� 10 ��
    if (params.size() > 1)
        nCount = params[1].get_int(); // ��ȡ������
    int nFrom = 0; // Ҫ�����Ľ�������Ĭ�� 0 ��
    if (params.size() > 2)
        nFrom = params[2].get_int(); // ��ȡҪ�����Ľ�����
    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 3)
        if(params[3].get_bool())
            filter = filter | ISMINE_WATCH_ONLY; // ���� watchonly

    if (nCount < 0) // �������Ǹ�
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0) // Ҫ�����Ľ������Ǹ�
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR); // �����������͵Ľ����

    const CWallet::TxItems & txOrdered = pwalletMain->wtxOrdered; // ��ȡ����Ľ����б�

    // iterate backwards until we have nCount items to return: // ��������ֱ�������� nCount ����Ŀ����
    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    { // ��������Ľ����б�
        CWalletTx *const pwtx = (*it).second.first; // ��ȡǮ������
        if (pwtx != 0)
            ListTransactions(*pwtx, strAccount, 0, true, ret, filter); // ��ȡ������Ϣ�������
        CAccountingEntry *const pacentry = (*it).second.second; // ��ȡ��Ӧ���˻���Ŀ
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret); // �˻���Ŀת��Ϊ JSON ��ʽ

        if ((int)ret.size() >= (nCount+nFrom)) break; // ���������С���ڵ��� Ҫ��ȡ�Ľ���������Ҫ�������������ĺͣ�����
    }
    // ret is newest to oldest // ������Ǵ����µ����

    if (nFrom > (int)ret.size()) // �������СС��Ҫ�����Ľ�����
        nFrom = ret.size(); // Ҫ�����Ľ��������ڽ������С
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    vector<UniValue> arrTmp = ret.getValues(); // ��ȡ������е�������Ϊ��ʱ����

    vector<UniValue>::iterator first = arrTmp.begin();
    std::advance(first, nFrom); // ���� first ������ nFrom
    vector<UniValue>::iterator last = arrTmp.begin();
    std::advance(last, nFrom+nCount); // ���� last ������ nFrom+nCount

    if (last != arrTmp.end()) arrTmp.erase(last, arrTmp.end()); // ����β�����ಿ��
    if (first != arrTmp.begin()) arrTmp.erase(arrTmp.begin(), first); // ����ͷ�����ಿ��

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest // ��ת��Ϊ���ϵ����£��б���ϵ��£���->��

    ret.clear(); // ��ս����
    ret.setArray(); // ����Ϊ��������
    ret.push_backV(arrTmp); // ������ʱ����

    return ret; // ���ؽ����
}

UniValue listaccounts(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() > 2) // ������� 2 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    int nMinDepth = 1; // ��С���
    if (params.size() > 0)
        nMinDepth = params[0].get_int(); // ��ȡָ�����
    isminefilter includeWatchonly = ISMINE_SPENDABLE;
    if(params.size() > 1)
        if(params[1].get_bool())
            includeWatchonly = includeWatchonly | ISMINE_WATCH_ONLY; // ���� watchonly

    map<string, CAmount> mapAccountBalances; // �˻����ӳ���б�
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& entry, pwalletMain->mapAddressBook) { // ������ַ��
        if (IsMine(*pwalletMain, entry.first) & includeWatchonly) // This address belongs to me // �õ�ַ������
            mapAccountBalances[entry.second.name] = 0; // �����˻����ӳ���б�����ʼ�����Ϊ 0
    }

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    { // ����Ǯ�����������б�
        const CWalletTx& wtx = (*it).second; // ��ȡǮ������
        CAmount nFee; // ���׷�
        string strSentAccount; // �����˻���
        list<COutputEntry> listReceived; // �����б�
        list<COutputEntry> listSent; // �����б�
        int nDepth = wtx.GetDepthInMainChain(); // ��ȡ�ý��׵����
        if (wtx.GetBlocksToMaturity() > 0 || nDepth < 0) // δ���� �� δ���������С�� 0��
            continue; // ����
        wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, includeWatchonly); // ��ȡ��ؽ��
        mapAccountBalances[strSentAccount] -= nFee; // �˻�����ȥ���׷�
        BOOST_FOREACH(const COutputEntry& s, listSent) // ���������б�
            mapAccountBalances[strSentAccount] -= s.amount; // �˻�����ȥ���͵Ľ��
        if (nDepth >= nMinDepth) // ������ȴ��ڵ�����С���
        {
            BOOST_FOREACH(const COutputEntry& r, listReceived) // ���������б�
                if (pwalletMain->mapAddressBook.count(r.destination)) // ��Ŀ���ַ�����ڵ�ַ����
                    mapAccountBalances[pwalletMain->mapAddressBook[r.destination].name] += r.amount; // ��Ӧ�˻������Ͻ��ս��
                else
                    mapAccountBalances[""] += r.amount; // ����Ĭ���˻������ϸý��ս��
        }
    }

    const list<CAccountingEntry> & acentries = pwalletMain->laccentries; // ��ȡ�˻���Ŀ�б�
    BOOST_FOREACH(const CAccountingEntry& entry, acentries) // �������б�
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit; // ����

    UniValue ret(UniValue::VOBJ); // �����������ͽ��
    BOOST_FOREACH(const PAIRTYPE(string, CAmount)& accountBalance, mapAccountBalances) { // �����˻����ӳ���б�
        ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second))); // �˻����������Լ�������
    }
    return ret; // ���ؽ��
}

UniValue listsinceblock(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp) // ֻ���������Ϣ
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    CBlockIndex *pindex = NULL; // ��ĳ�����鿪ʼ
    int target_confirms = 1; // ȷ������Ĭ��Ϊ 1
    isminefilter filter = ISMINE_SPENDABLE; // watchonly

    if (params.size() > 0) // �� 1 �����ϵĲ���
    {
        uint256 blockId;

        blockId.SetHex(params[0].get_str()); // ��ȡ��������
        BlockMap::iterator it = mapBlockIndex.find(blockId); // ����������ӳ���б��в��Ҹ�����
        if (it != mapBlockIndex.end()) // ���ҵ�
            pindex = it->second; // ��ȡ����������ָ��
    }

    if (params.size() > 1) // �������� 2 ������
    {
        target_confirms = params[1].get_int(); // ��ȡȷ����

        if (target_confirms < 1) // ȷ������СΪ 1
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    if(params.size() > 2) // �������� 3 ������
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY; // ���� watchonly

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1; // ��ȡָ����������

    UniValue transactions(UniValue::VARR); // �����������͵Ľ�����Ϣ��

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++) // ����Ǯ������ӳ���б�
    {
        CWalletTx tx = (*it).second; // ��ȡǮ������

        if (depth == -1 || tx.GetDepthInMainChain() < depth) // ��δָ������ �� �ý������С��ָ���������
            ListTransactions(tx, "*", 0, true, transactions, filter); // ��Ǯ������Ϊ������ȡ������Ϣ��
    }

    CBlockIndex *pblockLast = chainActive[chainActive.Height() + 1 - target_confirms]; // ��ȷ����Ϊ 1����ȡ�����������
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : uint256(); // ��ȡ�������ϣֵ

    UniValue ret(UniValue::VOBJ); // �������͵Ľ��
    ret.push_back(Pair("transactions", transactions)); // ���׼�
    ret.push_back(Pair("lastblock", lastblock.GetHex())); // ��������ϣֵ

    return ret; // ���ؽ������
}

UniValue gettransaction(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 2) // ����Ϊ 1 �� 2 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    uint256 hash;
    hash.SetHex(params[0].get_str()); // ��ȡ���׹�ϣ

    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 1)
        if(params[1].get_bool())
            filter = filter | ISMINE_WATCH_ONLY; // ���� watch-only ѡ��

    UniValue entry(UniValue::VOBJ);
    if (!pwalletMain->mapWallet.count(hash)) // ��֤Ǯ�����Ƿ���ڸý���
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    const CWalletTx& wtx = pwalletMain->mapWallet[hash]; // ��ȡ������Ӧ��Ǯ������

    CAmount nCredit = wtx.GetCredit(filter); // ������
    CAmount nDebit = wtx.GetDebit(filter); // ������
    CAmount nNet = nCredit - nDebit; // ��׬
    CAmount nFee = (wtx.IsFromMe(filter) ? wtx.GetValueOut() - nDebit : 0); // ���׷�

    entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee))); // ���
    if (wtx.IsFromMe(filter)) // ����ý��������Լ������ͣ�
        entry.push_back(Pair("fee", ValueFromAmount(nFee))); // ���

    WalletTxToJSON(wtx, entry); // Ǯ������ת��Ϊ JSON ��ʽ

    UniValue details(UniValue::VARR);
    ListTransactions(wtx, "*", 0, false, details, filter); // ��ȡ����ϸ��
    entry.push_back(Pair("details", details)); // ����ϸ����Ϣ

    string strHex = EncodeHexTx(static_cast<CTransaction>(wtx)); // ��Ǯ�����׽��� 16 ���Ʊ���
    entry.push_back(Pair("hex", strHex)); // ���׵� 16 ���Ʊ�����ʽ���ǽ���������

    return entry; // ���ؽ������
}

UniValue abandontransaction(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;

    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // ����

    uint256 hash;
    hash.SetHex(params[0].get_str()); // ��ȡ��������

    if (!pwalletMain->mapWallet.count(hash)) // ���ָ�������Ƿ���Ǯ����
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    if (!pwalletMain->AbandonTransaction(hash)) // ��Ǹ�Ǯ������Ϊ������
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");

    return NullUniValue; // ���ؿ�
}


UniValue backupwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
            "backupwallet \"destination\"\n"
            "\nSafely copies wallet.dat to destination, which can be a directory or a path with filename.\n"
            "\nArguments:\n"
            "1. \"destination\"   (string) The destination directory or file\n"
            "\nExamples:\n"
            + HelpExampleCli("backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("backupwallet", "\"backup.dat\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    string strDest = params[0].get_str(); // ��ȡָ�������Ŀ��
    if (!BackupWallet(*pwalletMain, strDest))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");

    return NullUniValue; // ���ؿ�ֵ
}


UniValue keypoolrefill(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ��Ǯ����ǰ����
        return NullUniValue;
    
    if (fHelp || params.size() > 1) // ���� 1 ������
        throw runtime_error( // �����������
            "keypoolrefill ( newsize )\n"
            "\nFills the keypool."
            + HelpRequiringPassphrase() + "\n"
            "\nArguments\n"
            "1. newsize     (numeric, optional, default=100) The new keypool size\n"
            "\nExamples:\n"
            + HelpExampleCli("keypoolrefill", "")
            + HelpExampleRpc("keypoolrefill", "")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -keypool
    unsigned int kpSize = 0; // 0 ��ʾͨ�� TopUpKeyPool() ���� -keypool ѡ���Ĭ����Կ�ش�С
    if (params.size() > 0) {
        if (params[0].get_int() < 0) // ��Կ�ش�С����С�� 0
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)params[0].get_int(); // ��ȡ��Կ�ش�С
    }

    EnsureWalletIsUnlocked(); // ȷ��Ǯ����ǰδ����
    pwalletMain->TopUpKeyPool(kpSize); // ����ָ����С�����Կ��

    if (pwalletMain->GetKeyPoolSize() < kpSize) // �������Կ�ش�С����С�� kpSize
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");

    return NullUniValue; // ���ؿ�ֵ
}


static void LockWallet(CWallet* pWallet)
{
    LOCK(cs_nWalletUnlockTime);
    nWalletUnlockTime = 0;
    pWallet->Lock();
}

UniValue walletpassphrase(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ��Ǯ������
        return NullUniValue;
    
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2)) // ������������Ϊ 2 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    if (fHelp) // Ǯ��δ����ʱ�޷��鿴���������
        return true;
    if (!pwalletMain->IsCrypted()) // Ǯ��δ����ʱ�޷�ִ�и�����
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");

    // Note that the walletpassphrase is stored in params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100); // Ԥ���� 100 ���ֽڵĿռ�
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    strWalletPass = params[0].get_str().c_str(); // ��ȡ�û�ָ����Ǯ������

    if (strWalletPass.length() > 0) // ���볤�ȱ������ 0
    {
        if (!pwalletMain->Unlock(strWalletPass)) // ����Ǯ��
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }
    else
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    pwalletMain->TopUpKeyPool(); // ������Կ��

    int64_t nSleepTime = params[1].get_int64(); // ��ȡ��Կ����ʱ����Ϊ˯��ʱ��
    LOCK(cs_nWalletUnlockTime);
    nWalletUnlockTime = GetTime() + nSleepTime; // �ó���������
    RPCRunLater("lockwallet", boost::bind(LockWallet, pwalletMain), nSleepTime); // �Ժ���������Ǯ������

    return NullUniValue;
}


UniValue walletpassphrasechange(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ��Ǯ����ǰ����
        return NullUniValue;
    
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2)) // Ǯ���Ѽ��� �� ��������Ϊ 2 ��
        throw runtime_error( // �����������
            "walletpassphrasechange \"oldpassphrase\" \"newpassphrase\"\n"
            "\nChanges the wallet passphrase from 'oldpassphrase' to 'newpassphrase'.\n"
            "\nArguments:\n"
            "1. \"oldpassphrase\"      (string) The current passphrase\n"
            "2. \"newpassphrase\"      (string) The new passphrase\n"
            "\nExamples:\n"
            + HelpExampleCli("walletpassphrasechange", "\"old one\" \"new one\"")
            + HelpExampleRpc("walletpassphrasechange", "\"old one\", \"new one\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    if (fHelp) // ��Ǯ��δ���ܣ����޷���ʾ���������
        return true;
    if (!pwalletMain->IsCrypted()) // ��Ǯ��δ���ܣ����޷�ʹ�ø�����
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = params[0].get_str().c_str(); // ��ȡ�û�ָ���ľ�����

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = params[1].get_str().c_str(); // ��ȡ�û�ָ����������

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1) // �¾����볤�ȶ�����С�� 1
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass)) // �ı�Ǯ������
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    return NullUniValue; // ���ؿ�ֵ
}


UniValue walletlock(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ��Ǯ����ǰ����
        return NullUniValue;
    
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 0)) // Ǯ���Ѽ��� �� û�в���
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    if (fHelp) // Ǯ��δ����ʱ�޷��鿴���������
        return true;
    if (!pwalletMain->IsCrypted()) // Ǯ��δ����ʱ�޷�ʹ�ø�����
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");

    {
        LOCK(cs_nWalletUnlockTime);
        pwalletMain->Lock(); // ����Ǯ��
        nWalletUnlockTime = 0; // Ǯ����������ʱ���� 0
    }

    return NullUniValue; // ���ؿ�ֵ
}


UniValue encryptwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ��Ǯ����ǰ����
        return NullUniValue;
    
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() != 1)) // Ǯ��δ���� �� ����ֻ���� 1 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    if (fHelp) // Ǯ������ʱ���������������κ���Ϣ
        return true;
    if (pwalletMain->IsCrypted()) // ��Ǯ���Ѽ���
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strWalletPass; // ����һ����ȫ�ַ�������������������
    strWalletPass.reserve(100); // Ԥ���� 100 ���ַ��Ŀռ�
    strWalletPass = params[0].get_str().c_str(); // ��ȡ�û�ָ��������

    if (strWalletPass.length() < 1) // ���볤�Ȳ���С�� 1������Ϊ 1 ���ַ�
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwalletMain->EncryptWallet(strWalletPass)) // ����Ǯ��
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

    // BDB seems to have a bad habit of writing old data into // Berkeley DB �ƺ���һ����ϰ�ߣ�
    // slack space in .dat files; that is bad if the old data is // �Ѿ�����д�� .dat �ļ�����ɢ��
    // unencrypted private keys. So: // �����Ǿ�������û�м��ܵ�˽Կ�����ԣ�
    StartShutdown(); // �رպ��ķ�����
    return "wallet encrypted; Bitcoin server stopping, restart to run with encrypted wallet. The keypool has been flushed, you need to make a new backup."; // ���ظ���Ϣ��ʾ���ܳɹ�
}

UniValue lockunspent(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 2) // ����ֻ���� 1 ���� 2 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    if (params.size() == 1) // ��ֻ��һ������
        RPCTypeCheck(params, boost::assign::list_of(UniValue::VBOOL)); // ��֤��������
    else
        RPCTypeCheck(params, boost::assign::list_of(UniValue::VBOOL)(UniValue::VARR));

    bool fUnlock = params[0].get_bool(); // ��ȡ�ӽ�����״̬

    if (params.size() == 1) { // ��ֻ��һ������
        if (fUnlock) // ���ǽ���
            pwalletMain->UnlockAllCoins(); // ����ȫ��
        return true;
    }

    UniValue outputs = params[1].get_array(); // ��ȡ���������������
    for (unsigned int idx = 0; idx < outputs.size(); idx++) { // ����������
        const UniValue& output = outputs[idx]; // ��ȡһ�����󣨽������������
        if (!output.isObject())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected object");
        const UniValue& o = output.get_obj(); // ��ȡ�ö���

        RPCTypeCheckObj(o, boost::assign::map_list_of("txid", UniValue::VSTR)("vout", UniValue::VNUM)); // ���������ͣ�"��������" Ϊ�ַ�����"�����������" Ϊ������

        string txid = find_value(o, "txid").get_str(); // ��ȡ��������
        if (!IsHex(txid)) // �ж��Ƿ�Ϊ 16 ����
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");

        int nOutput = find_value(o, "vout").get_int(); // ��ȡ�����������
        if (nOutput < 0) // ��ֵ���ڵ��� 0
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        COutPoint outpt(uint256S(txid), nOutput); // ����һ����������

        if (fUnlock) // ������
            pwalletMain->UnlockCoin(outpt); // �����ý������
        else // ����
            pwalletMain->LockCoin(outpt); // �����ý������
    }

    return true; // �ɹ����� true
}

UniValue listlockunspent(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() > 0) // û�в���
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    vector<COutPoint> vOutpts; // ����������б�
    pwalletMain->ListLockedCoins(vOutpts); // ��ȡ�����Ľ����������

    UniValue ret(UniValue::VARR); // �����������͵Ľ����

    BOOST_FOREACH(COutPoint &outpt, vOutpts) { // ����������б�
        UniValue o(UniValue::VOBJ);

        o.push_back(Pair("txid", outpt.hash.GetHex())); // ��ȡ�����Ľ�������
        o.push_back(Pair("vout", (int)outpt.n)); // ��ȡ�������������
        ret.push_back(o); // ��������
    }

    return ret; // ���ؽ����
}

UniValue settxfee(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    // Amount
    CAmount nAmount = AmountFromValue(params[0]); // ��ȡָ�����׷ѣ�������Χ���

    payTxFee = CFeeRate(nAmount, 1000); // ���ý��׷�
    return true; // ���óɹ����� true
}

UniValue getwalletinfo(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ��Ǯ����ǰ����
        return NullUniValue;
    
    if (fHelp || params.size() != 0) // û�в���
        throw runtime_error( // �����������
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    UniValue obj(UniValue::VOBJ); // ����Ŀ�����Ͷ���
    obj.push_back(Pair("walletversion", pwalletMain->GetVersion())); // Ǯ���汾
    obj.push_back(Pair("balance",       ValueFromAmount(pwalletMain->GetBalance()))); // Ǯ�������ã���ȷ�ϣ��ѳ��죩
    obj.push_back(Pair("unconfirmed_balance", ValueFromAmount(pwalletMain->GetUnconfirmedBalance()))); // δȷ�����
    obj.push_back(Pair("immature_balance",    ValueFromAmount(pwalletMain->GetImmatureBalance()))); // δ�������
    obj.push_back(Pair("txcount",       (int)pwalletMain->mapWallet.size())); // ��Ǯ���ڵĽ�����
    obj.push_back(Pair("keypoololdest", pwalletMain->GetOldestKeyPoolTime())); // ��Կ���������Կ����ʱ��
    obj.push_back(Pair("keypoolsize",   (int)pwalletMain->GetKeyPoolSize())); // ��Կ�ش�С
    if (pwalletMain->IsCrypted()) // ��Ǯ���Ѽ���
        obj.push_back(Pair("unlocked_until", nWalletUnlockTime)); // ��������ʱ��
    obj.push_back(Pair("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK()))); // ���׷�
    return obj; // ���ؽ��
}

UniValue resendwallettransactions(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() != 0) // û�в���
        throw runtime_error( // �����������
            "resendwallettransactions\n"
            "Immediately re-broadcast unconfirmed wallet transactions to all peers.\n"
            "Intended only for testing; the wallet code periodically re-broadcasts\n"
            "automatically.\n"
            "Returns array of transaction ids that were re-broadcast.\n"
            );

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    std::vector<uint256> txids = pwalletMain->ResendWalletTransactionsBefore(GetTime()); // ���·���Ǯ�����ײ���ȡ��Щ���׵�����
    UniValue result(UniValue::VARR); // �������͵Ľ������
    BOOST_FOREACH(const uint256& txid, txids) // ���������б�
    {
        result.push_back(txid.ToString()); // ��������
    }
    return result; // ���ؽ��
}

UniValue listunspent(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() > 3) // ������� 3 ��
        throw runtime_error( // �����������
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

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)(UniValue::VNUM)(UniValue::VARR)); // ����������

    int nMinDepth = 1; // ��С��ȣ�Ĭ��Ϊ 1
    if (params.size() > 0)
        nMinDepth = params[0].get_int(); // ��ȡ��С���

    int nMaxDepth = 9999999; // �����ȣ�Ĭ��Ϊ 9999999
    if (params.size() > 1)
        nMaxDepth = params[1].get_int(); // ��ȡ������

    set<CBitcoinAddress> setAddress; // ���رҵ�ַ����
    if (params.size() > 2) { // ��ָ���˵�ַ��
        UniValue inputs = params[2].get_array(); // ��ȡ��ַ��
        for (unsigned int idx = 0; idx < inputs.size(); idx++) { // ������ַ��
            const UniValue& input = inputs[idx]; // ��ȡһ����ַ
            CBitcoinAddress address(input.get_str()); // ת��Ϊ�ַ�������װΪ���رҵ�ַ����
            if (!address.IsValid()) // ���õ�ַ��Ч��
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Bitcoin address: ")+input.get_str());
            if (setAddress.count(address)) // ��֤������û�иõ�ַ
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+input.get_str());
           setAddress.insert(address); // �����ַ����
        }
    }

    UniValue results(UniValue::VARR); // �����������͵Ľ����
    vector<COutput> vecOutputs; // ����б�
    assert(pwalletMain != NULL); // Ǯ������
    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������
    pwalletMain->AvailableCoins(vecOutputs, false, NULL, true); // ��ȡ�ɻ��ѵ�����б�
    BOOST_FOREACH(const COutput& out, vecOutputs) { // �������б�
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth) // ��ȣ�ȷ��������ָ����Χ��
            continue;

        if (setAddress.size()) { // ����ַ����С���� 0
            CTxDestination address;
            if (!ExtractDestination(out.tx->vout[out.i].scriptPubKey, address)) // ��������ű���ȡ��ַ
                continue;

            if (!setAddress.count(address)) // �鿴��ַ�����Ƿ񺬴˵�ַ
                continue;
        } // ���ࣿ

        CAmount nValue = out.tx->vout[out.i].nValue; // ��ȡ������
        const CScript& pk = out.tx->vout[out.i].scriptPubKey; // ��ȡ��Կ�ű�
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex())); // ����������16 ������ʽ��
        entry.push_back(Pair("vout", out.i)); // �����������
        CTxDestination address;
        if (ExtractDestination(out.tx->vout[out.i].scriptPubKey, address)) { // ���ݽ�������ű���ȡ���׵�ַ
            entry.push_back(Pair("address", CBitcoinAddress(address).ToString())); // ��������Ĺ�Կ��ַ
            if (pwalletMain->mapAddressBook.count(address)) // ���ڵ�ַ���в鵽�õ�ַ
                entry.push_back(Pair("account", pwalletMain->mapAddressBook[address].name)); // ��ȡ�ʻ���
        }
        entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end()))); // ��Կ�ű�
        if (pk.IsPayToScriptHash()) { // �Ƿ�֧�����ű���ϣ
            CTxDestination address;
            if (ExtractDestination(pk, address)) {
                const CScriptID& hash = boost::get<CScriptID>(address); // ͨ����ַ��ȡ�ű�����
                CScript redeemScript;
                if (pwalletMain->GetCScript(hash, redeemScript)) // ͨ��������ȡ��ؽű�
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }
        entry.push_back(Pair("amount",ValueFromAmount(nValue))); // �������
        entry.push_back(Pair("confirmations",out.nDepth)); // ȷ��������ȣ�
        entry.push_back(Pair("spendable", out.fSpendable)); // �Ƿ�ɻ���
        results.push_back(entry); // ��������
    }

    return results; // ���ؽ����
}

UniValue fundrawtransaction(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 1.ȷ����ǰǮ������
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2) // 2.����Ϊ 1 �� 2 ��
        throw runtime_error( // �����������
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

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VBOOL)); // 3.����������

    // parse hex string from parameter
    CTransaction origTx; // ԭʼ����
    if (!DecodeHexTx(origTx, params[0].get_str())) // �Ӳ������� 16 �����ַ���
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    if (origTx.vout.size() == 0) // ���׵�����б���Ϊ��
        throw JSONRPCError(RPC_INVALID_PARAMETER, "TX must have at least one output");

    bool includeWatching = false; // �Ƿ���� watch-only ��ַ��Ĭ�ϲ�����
    if (params.size() > 1)
        includeWatching = params[1].get_bool(); // ��ȡ�û�����

    CMutableTransaction tx(origTx); // 4.����һ�ʿɱ�汾�Ľ���
    CAmount nFee; // ���׷�
    string strFailReason;
    int nChangePos = -1; // �ı�λ��
    if(!pwalletMain->FundTransaction(tx, nFee, nChangePos, strFailReason, includeWatching)) // �������ף�����������������������еĻ���
        throw JSONRPCError(RPC_INTERNAL_ERROR, strFailReason);

    UniValue result(UniValue::VOBJ); // 5.�����������ͽ����
    result.push_back(Pair("hex", EncodeHexTx(tx))); // 16 ���Ʊ��뽻��
    result.push_back(Pair("changepos", nChangePos)); // �ı�λ��
    result.push_back(Pair("fee", ValueFromAmount(nFee))); // ���׷�

    return result; // ���ؽ����
}
