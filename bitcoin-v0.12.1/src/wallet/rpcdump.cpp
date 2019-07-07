// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "chain.h"
#include "rpcserver.h"
#include "init.h"
#include "main.h"
#include "script/script.h"
#include "script/standard.h"
#include "sync.h"
#include "util.h"
#include "utiltime.h"
#include "wallet.h"

#include <fstream>
#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <univalue.h>

#include <boost/foreach.hpp>

using namespace std;

void EnsureWalletIsUnlocked();
bool EnsureWalletIsAvailable(bool avoidException);

std::string static EncodeDumpTime(int64_t nTime) {
    return DateTimeStrFormat("%Y-%m-%dT%H:%M:%SZ", nTime);
}

int64_t static DecodeDumpTime(const std::string &str) {
    static const boost::posix_time::ptime epoch = boost::posix_time::from_time_t(0);
    static const std::locale loc(std::locale::classic(),
        new boost::posix_time::time_input_facet("%Y-%m-%dT%H:%M:%SZ"));
    std::istringstream iss(str);
    iss.imbue(loc);
    boost::posix_time::ptime ptime(boost::date_time::not_a_date_time);
    iss >> ptime;
    if (ptime.is_not_a_date_time())
        return 0;
    return (ptime - epoch).total_seconds();
}

std::string static EncodeDumpString(const std::string &str) {
    std::stringstream ret;
    BOOST_FOREACH(unsigned char c, str) {
        if (c <= 32 || c >= 128 || c == '%') {
            ret << '%' << HexStr(&c, &c + 1);
        } else {
            ret << c;
        }
    }
    return ret.str();
}

std::string DecodeDumpString(const std::string &str) {
    std::stringstream ret;
    for (unsigned int pos = 0; pos < str.length(); pos++) {
        unsigned char c = str[pos];
        if (c == '%' && pos+2 < str.length()) {
            c = (((str[pos+1]>>6)*9+((str[pos+1]-'0')&15)) << 4) | 
                ((str[pos+2]>>6)*9+((str[pos+2]-'0')&15));
            pos += 2;
        }
        ret << c;
    }
    return ret.str();
}

UniValue importprivkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 3) // ��������Ϊ 1 ��������Ϊ 3 ��
        throw runtime_error( // �����������
            "importprivkey \"bitcoinprivkey\" ( \"label\" rescan )\n"
            "\nAdds a private key (as returned by dumpprivkey) to your wallet.\n"
            "\nArguments:\n"
            "1. \"bitcoinprivkey\"   (string, required) The private key (see dumpprivkey)\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nDump a private key\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"") +
            "\nImport the private key with rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\"") +
            "\nImport using a label and without rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importprivkey", "\"mykey\", \"testing\", false")
        );


    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    EnsureWalletIsUnlocked(); // ȷ��Ǯ����ǰ���ڽ���״̬

    string strSecret = params[0].get_str(); // ��ȡָ����˽Կ
    string strLabel = ""; // ��ǩ���˻�����Ĭ��Ϊ ""
    if (params.size() > 1)
        strLabel = params[1].get_str(); // ��ȡָ�����ʻ���

    // Whether to perform rescan after import // �ڵ���˽Կ���Ƿ�ִ����ɨ��
    bool fRescan = true; // ��ɨ���־��Ĭ�ϴ�
    if (params.size() > 2)
        fRescan = params[2].get_bool(); // ��ȡָ������ɨ������

    if (fRescan && fPruneMode) // ��ɨ��ģʽ���޼�ģʽ����ͬʱ���������߲�����
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret); // ��ʼ�����ر���Կ����

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");

    CKey key = vchSecret.GetKey(); // ��ȡ˽Կ
    if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

    CPubKey pubkey = key.GetPubKey(); // ��ȡ��Կ
    assert(key.VerifyPubKey(pubkey)); // ��֤��˽Կ�Ƿ����
    CKeyID vchAddress = pubkey.GetID(); // ��ȡ��Կ����
    {
        pwalletMain->MarkDirty(); // ���Ǯ���Ըı�
        pwalletMain->SetAddressBook(vchAddress, strLabel, "receive"); // ���õ�ַ���������˻�ָ����;

        // Don't throw error in case a key is already there
        if (pwalletMain->HaveKey(vchAddress)) // ����Կ�Ѵ��ڣ����׳�����
            return NullUniValue; // ֱ�ӷ��ؿ�ֵ

        pwalletMain->mapKeyMetadata[vchAddress].nCreateTime = 1; // ��ʼ������ʱ��Ϊ 1

        if (!pwalletMain->AddKeyPubKey(key, pubkey)) // ��ӹ�˽Կ��Ǯ��
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        // whenever a key is imported, we need to scan the whole chain // ���ۺ�ʱ������Կ�����Ƕ���Ҫɨ��������
        pwalletMain->nTimeFirstKey = 1; // 0 would be considered 'no value' // 0 �ᱻ���� 'û�м�ֵ'

        if (fRescan) { // ��������ɨ��
            pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true); // ��ɨ������Ǯ������
        }
    }

    return NullUniValue; // �ɹ����ؿ�ֵ
}

void ImportAddress(const CBitcoinAddress& address, const string& strLabel); // �����ַ��Ǯ��
void ImportScript(const CScript& script, const string& strLabel, bool isRedeemScript) // ����ű�
{
    if (!isRedeemScript && ::IsMine(*pwalletMain, script) == ISMINE_SPENDABLE) // P2SH ���� �� ���Լ��Ľű�
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");

    pwalletMain->MarkDirty(); // ���Ǯ���Ѹı�

    if (!pwalletMain->HaveWatchOnly(script) && !pwalletMain->AddWatchOnly(script)) // �� watch-only ������û��ָ���ű�������Ӹýű��� watch-only �ű�����
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");

    if (isRedeemScript) { // ��Ϊ��ؽű�
        if (!pwalletMain->HaveCScript(script) && !pwalletMain->AddCScript(script))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding p2sh redeemScript to wallet");
        ImportAddress(CBitcoinAddress(CScriptID(script)), strLabel); // �����ַ�������˻�
    }
}

void ImportAddress(const CBitcoinAddress& address, const string& strLabel)
{
    CScript script = GetScriptForDestination(address.Get()); // ͨ���ű�������ȡ�ű�
    ImportScript(script, strLabel, false); // ����ű�
    // add to address book or update label // ��ӵ���ַ��������˻�
    if (address.IsValid()) // ���õ�ַ��Ч
        pwalletMain->SetAddressBook(address.Get(), strLabel, "receive"); // ��ӵ�ַ�������˻�����;����ַ��
}

UniValue importaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 4) // ��������Ϊ 1 ������� 4 ��
        throw runtime_error( // �����������
            "importaddress \"address\" ( \"label\" rescan p2sh )\n"
            "\nAdds a script (in hex) or address that can be watched as if it were in your wallet but cannot be used to spend.\n"
            "\nArguments:\n"
            "1. \"script\"           (string, required) The hex-encoded script (or address)\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "4. p2sh                 (boolean, optional, default=false) Add the P2SH version of the script as well\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "If you have the full public key, you should call importpublickey instead of this.\n"
            "\nExamples:\n"
            "\nImport a script with rescan\n"
            + HelpExampleCli("importaddress", "\"myscript\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("importaddress", "\"myscript\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importaddress", "\"myscript\", \"testing\", false")
        );


    string strLabel = ""; // �˻�����Ĭ��Ϊ ""
    if (params.size() > 1)
        strLabel = params[1].get_str(); // ��ȡ�˻�����ű�

    // Whether to perform rescan after import // �ڵ�����Ƿ�ִ����ɨ��
    bool fRescan = true; // ��ɨ��ѡ�Ĭ�Ͽ���
    if (params.size() > 2)
        fRescan = params[2].get_bool(); // ��ȡ��ɨ������

    if (fRescan && fPruneMode) // ��ɨ����޼�ģʽ���ܼ���
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    // Whether to import a p2sh version, too
    bool fP2SH = false; // �Ƿ�Ҳ���� p2sh �汾�Ľű�
    if (params.size() > 3)
        fP2SH = params[3].get_bool(); // ��ȡѡ������

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    CBitcoinAddress address(params[0].get_str()); // ��ʼ�����رҵ�ַ
    if (address.IsValid()) { // ����ַ��Ч
        if (fP2SH) // �������� P2SH ��־
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot use the p2sh flag with an address - use a script instead"); // �׳��쳣
        ImportAddress(address, strLabel); // �����ַ��������˻�
    } else if (IsHex(params[0].get_str())) { // ����ַ��Ч�������ǽű�
        std::vector<unsigned char> data(ParseHex(params[0].get_str())); // �ѽű����� vector ������
        ImportScript(CScript(data.begin(), data.end()), strLabel, fP2SH); // ����ű�
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address or script");
    }

    if (fRescan) // ����ɨ�迪��
    {
        pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true); // ��ɨ��Ǯ������
        pwalletMain->ReacceptWalletTransactions(); // �ѽ��׷����ڴ��
    }

    return NullUniValue; // ���ؿ�ֵ
}

UniValue importpubkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 4) // �������� 1 ������� 3 �����������
        throw runtime_error( // �����������
            "importpubkey \"pubkey\" ( \"label\" rescan )\n"
            "\nAdds a public key (in hex) that can be watched as if it were in your wallet but cannot be used to spend.\n"
            "\nArguments:\n"
            "1. \"pubkey\"           (string, required) The hex-encoded public key\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nImport a public key with rescan\n"
            + HelpExampleCli("importpubkey", "\"mypubkey\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("importpubkey", "\"mypubkey\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importpubkey", "\"mypubkey\", \"testing\", false")
        );


    string strLabel = ""; // �ʻ�����Ĭ��Ϊ ""
    if (params.size() > 1)
        strLabel = params[1].get_str(); // ��ȡָ�����ʻ���

    // Whether to perform rescan after import // �ڵ���֮���Ƿ�ִ����ɨ��
    bool fRescan = true; // ��ɨ��ѡ�Ĭ�Ͽ���
    if (params.size() > 2)
        fRescan = params[2].get_bool(); // ��ȡ��ɨ������

    if (fRescan && fPruneMode) // ��ɨ�����޼�ģʽ������
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    if (!IsHex(params[0].get_str())) // ��Կ����Ϊ 16 ����
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey must be a hex string");
    std::vector<unsigned char> data(ParseHex(params[0].get_str()));
    CPubKey pubKey(data.begin(), data.end()); // ��ʼ����Կ
    if (!pubKey.IsFullyValid()) // �ù�Կ�Ƿ���Ч
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey is not a valid public key");

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    ImportAddress(CBitcoinAddress(pubKey.GetID()), strLabel); // �����ַ�������˻�
    ImportScript(GetScriptForRawPubKey(pubKey), strLabel, false); // ����ű�

    if (fRescan) // ����������ɨ��
    {
        pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true); // ��ɨ��Ǯ������
        pwalletMain->ReacceptWalletTransactions(); // �ѽ��׷����ڴ��
    }

    return NullUniValue; // ���ؿ�ֵ
}


UniValue importwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
            "importwallet \"filename\"\n"
            "\nImports keys from a wallet dump file (see dumpwallet).\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The wallet file\n"
            "\nExamples:\n"
            "\nDump the wallet\n"
            + HelpExampleCli("dumpwallet", "\"test\"") +
            "\nImport the wallet\n"
            + HelpExampleCli("importwallet", "\"test\"") +
            "\nImport using the json rpc call\n"
            + HelpExampleRpc("importwallet", "\"test\"")
        );

    if (fPruneMode) // ����Ǯ�����޼�ģʽ����Ч
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing wallets is disabled in pruned mode");

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    EnsureWalletIsUnlocked(); // ȷ��Ǯ����ʱδ����

    ifstream file; // �ļ�����������
    file.open(params[0].get_str().c_str(), std::ios::in | std::ios::ate); // ��ָ���ļ������̶�λ���ļ�����β
    if (!file.is_open()) // �ж��ļ��Ĵ�״̬
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    int64_t nTimeBegin = chainActive.Tip()->GetBlockTime(); // ��ȡ������鴴��ʱ��

    bool fGood = true;

    int64_t nFilesize = std::max((int64_t)1, (int64_t)file.tellg()); // ͨ���ļ�ָ���λ�û�ȡ�ļ���С��������ʾ���ؽ���
    file.seekg(0, file.beg); // �ļ�ָ�붨λ���ļ�����ͷ

    pwalletMain->ShowProgress(_("Importing..."), 0); // show progress dialog in GUI
    while (file.good()) { // �ļ���״̬����ʱ
        pwalletMain->ShowProgress("", std::max(1, std::min(99, (int)(((double)file.tellg() / (double)nFilesize) * 100))));
        std::string line;
        std::getline(file, line); // ��ȡһ��
        if (line.empty() || line[0] == '#') // ������Ϊ�� �� �����ַ�Ϊ '#'
            continue; // �������� �� ע����

        std::vector<std::string> vstr;
        boost::split(vstr, line, boost::is_any_of(" ")); // ���ո� " " �ָ��ַ���
        if (vstr.size() < 2) // �ַ����������ܵ��� 2 ��
            continue;
        CBitcoinSecret vchSecret;
        if (!vchSecret.SetString(vstr[0])) // Base58 �����˽Կ
            continue;
        CKey key = vchSecret.GetKey(); // ��ȡ˽Կ
        CPubKey pubkey = key.GetPubKey(); // ����õ���Կ
        assert(key.VerifyPubKey(pubkey)); // ��֤��Կ˽Կ�Ƿ�ƥ��
        CKeyID keyid = pubkey.GetID(); // ��ȡ��Կ������Ϊ��Կ����
        if (pwalletMain->HaveKey(keyid)) { // �����Կ������Ӧ��Կ�Ƿ����
            LogPrintf("Skipping import of %s (key already present)\n", CBitcoinAddress(keyid).ToString());
            continue;
        }
        int64_t nTime = DecodeDumpTime(vstr[1]); // ��ȡ������ʱ��
        std::string strLabel; // ���� label ��ǩ��ֵ���˻���
        bool fLabel = true; // �˻���־��Ĭ��Ϊ true
        for (unsigned int nStr = 2; nStr < vstr.size(); nStr++) { // ��������������ǩ���
            if (boost::algorithm::starts_with(vstr[nStr], "#")) // û�б�ǩ��ֱ������
                break;
            if (vstr[nStr] == "change=1")
                fLabel = false;
            if (vstr[nStr] == "reserve=1")
                fLabel = false;
            if (boost::algorithm::starts_with(vstr[nStr], "label=")) {
                strLabel = DecodeDumpString(vstr[nStr].substr(6)); // ���±�Ϊ 6 ���ַ���ʼ��ȡ�ִ�
                fLabel = true; // �˻���־��Ϊ true
            }
        }
        LogPrintf("Importing %s...\n", CBitcoinAddress(keyid).ToString()); // ��¼���빫Կ��ַ
        if (!pwalletMain->AddKeyPubKey(key, pubkey)) { // �ѹ�˽����ӵ�Ǯ��
            fGood = false;
            continue;
        }
        pwalletMain->mapKeyMetadata[keyid].nCreateTime = nTime; // ����˽Կ����ʱ��
        if (fLabel) // ������Կ�������˻�
            pwalletMain->SetAddressBook(keyid, strLabel, "receive"); // ���õ���ַ���������������˻���
        nTimeBegin = std::min(nTimeBegin, nTime);
    }
    file.close(); // �ر��ļ�������
    pwalletMain->ShowProgress("", 100); // hide progress dialog in GUI

    CBlockIndex *pindex = chainActive.Tip(); // ��ȡ������������ָ��
    while (pindex && pindex->pprev && pindex->GetBlockTime() > nTimeBegin - 7200)
        pindex = pindex->pprev; // Ѱ��ʱ����� 2h �Ŀ�

    if (!pwalletMain->nTimeFirstKey || nTimeBegin < pwalletMain->nTimeFirstKey)
        pwalletMain->nTimeFirstKey = nTimeBegin;

    LogPrintf("Rescanning last %i blocks\n", chainActive.Height() - pindex->nHeight + 1);
    pwalletMain->ScanForWalletTransactions(pindex); // ��ĳ���鿪ʼɨ����ϵĽ���
    pwalletMain->MarkDirty(); // ���Ǯ���Ѹı�

    if (!fGood) // ĳ����Կ��ӵ�Ǯ��ʧ��
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");

    return NullUniValue; // ���ؿ�ֵ
}

UniValue dumpprivkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
            "dumpprivkey \"bitcoinaddress\"\n"
            "\nReveals the private key corresponding to 'bitcoinaddress'.\n"
            "Then the importprivkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"bitcoinaddress\"   (string, required) The bitcoin address for the private key\n"
            "\nResult:\n"
            "\"key\"                (string) The private key\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"")
            + HelpExampleCli("importprivkey", "\"mykey\"")
            + HelpExampleRpc("dumpprivkey", "\"myaddress\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    EnsureWalletIsUnlocked(); // ȷ��Ǯ����ǰ������Ϊ���ܻ�����˵����ڽ���״̬��

    string strAddress = params[0].get_str(); // ��ȡָ���Ĺ�Կ��ַ
    CBitcoinAddress address;
    if (!address.SetString(strAddress)) // ��ʼ��һ�����رҵ�ַ����
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    CKeyID keyID;
    if (!address.GetKeyID(keyID)) // ��ȡ�õ�ַ������
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CKey vchSecret;
    if (!pwalletMain->GetKey(keyID, vchSecret)) // ͨ��������ȡ��Ӧ��˽Կ
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    return CBitcoinSecret(vchSecret).ToString(); // ��˽Կ���� Base58 ���벢���ؽ��
}


UniValue dumpwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // ȷ����ǰǮ������
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
            "dumpwallet \"filename\"\n"
            "\nDumps all wallet keys in a human-readable format.\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The filename\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpwallet", "\"test\"")
            + HelpExampleRpc("dumpwallet", "\"test\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // Ǯ������

    EnsureWalletIsUnlocked(); // ȷ����ǰǮ��δ����

    ofstream file; // �ļ����������
    file.open(params[0].get_str().c_str()); // ��ָ���ļ�
    if (!file.is_open()) // �����ļ�״̬
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    std::map<CKeyID, int64_t> mapKeyBirth; // ��Կ����ʱ��
    std::set<CKeyID> setKeyPool; // ��Կ�ؼ���
    pwalletMain->GetKeyBirthTimes(mapKeyBirth); // ��ȡǮ����Կ����ʱ��
    pwalletMain->GetAllReserveKeys(setKeyPool); // ��ȡ����Ԥ��������Կ

    // sort time/key pairs
    std::vector<std::pair<int64_t, CKeyID> > vKeyBirth; // ��Կ����ʱ��ӳ���б�
    for (std::map<CKeyID, int64_t>::const_iterator it = mapKeyBirth.begin(); it != mapKeyBirth.end(); it++) {
        vKeyBirth.push_back(std::make_pair(it->second, it->first)); // �� map �ڵ����ݵ��� vector
    }
    mapKeyBirth.clear(); // ��� map
    std::sort(vKeyBirth.begin(), vKeyBirth.end()); // �Ը��б�����ʱ���������Ĭ������

    // produce output
    file << strprintf("# Wallet dump created by Bitcoin %s (%s)\n", CLIENT_BUILD, CLIENT_DATE); // �ͻ��˰汾
    file << strprintf("# * Created on %s\n", EncodeDumpTime(GetTime())); // ��ǰʱ��
    file << strprintf("# * Best block at time of backup was %i (%s),\n", chainActive.Height(), chainActive.Tip()->GetBlockHash().ToString()); // ��ѿ�ĸ߶Ⱥ͹�ϣ
    file << strprintf("#   mined on %s\n", EncodeDumpTime(chainActive.Tip()->GetBlockTime())); // ��ѿ������ʱ��
    file << "\n";
    for (std::vector<std::pair<int64_t, CKeyID> >::const_iterator it = vKeyBirth.begin(); it != vKeyBirth.end(); it++) {
        const CKeyID &keyid = it->second; // ��ȡ��Կ����
        std::string strTime = EncodeDumpTime(it->first); // ����ʱ�䣬��һ���ĸ�ʽ���
        std::string strAddr = CBitcoinAddress(keyid).ToString(); // ��ȡ��Կ��ַ
        CKey key; // ˽Կ
        if (pwalletMain->GetKey(keyid, key)) { // ͨ����Կ������ȡ��Ӧ˽Կ
            if (pwalletMain->mapAddressBook.count(keyid)) { // ��Կ���������ڵ�ַ��ӳ���б�
                file << strprintf("%s %s label=%s # addr=%s\n", CBitcoinSecret(key).ToString(), strTime, EncodeDumpString(pwalletMain->mapAddressBook[keyid].name), strAddr); // label=
            } else if (setKeyPool.count(keyid)) { // ��Կ������������Կ�ؼ���
                file << strprintf("%s %s reserve=1 # addr=%s\n", CBitcoinSecret(key).ToString(), strTime, strAddr); // reserve=1
            } else { // ��������
                file << strprintf("%s %s change=1 # addr=%s\n", CBitcoinSecret(key).ToString(), strTime, strAddr); // change=1
            }
        }
    }
    file << "\n";
    file << "# End of dump\n"; // ��������
    file.close(); // �ر��ļ������
    return NullUniValue; // ���ؿ�ֵ
}
