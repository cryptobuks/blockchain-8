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
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 3) // 参数至少为 1 个，至多为 3 个
        throw runtime_error( // 命令帮助反馈
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


    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    EnsureWalletIsUnlocked(); // 确保钱包当前处于解密状态

    string strSecret = params[0].get_str(); // 获取指定的私钥
    string strLabel = ""; // 标签（账户），默认为 ""
    if (params.size() > 1)
        strLabel = params[1].get_str(); // 获取指定的帐户名

    // Whether to perform rescan after import // 在导入私钥后是否执行再扫描
    bool fRescan = true; // 再扫描标志，默认打开
    if (params.size() > 2)
        fRescan = params[2].get_bool(); // 获取指定的再扫描设置

    if (fRescan && fPruneMode) // 再扫描模式和修剪模式不能同时开启，二者不兼容
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret); // 初始化比特币密钥对象

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");

    CKey key = vchSecret.GetKey(); // 获取私钥
    if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

    CPubKey pubkey = key.GetPubKey(); // 获取公钥
    assert(key.VerifyPubKey(pubkey)); // 验证公私钥是否配对
    CKeyID vchAddress = pubkey.GetID(); // 获取公钥索引
    {
        pwalletMain->MarkDirty(); // 标记钱包以改变
        pwalletMain->SetAddressBook(vchAddress, strLabel, "receive"); // 设置地址簿并关联账户指定用途

        // Don't throw error in case a key is already there
        if (pwalletMain->HaveKey(vchAddress)) // 若密钥已存在，不抛出错误
            return NullUniValue; // 直接返回空值

        pwalletMain->mapKeyMetadata[vchAddress].nCreateTime = 1; // 初始化创建时间为 1

        if (!pwalletMain->AddKeyPubKey(key, pubkey)) // 添加公私钥到钱包
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        // whenever a key is imported, we need to scan the whole chain // 无论何时导入密钥，我们都需要扫描整个链
        pwalletMain->nTimeFirstKey = 1; // 0 would be considered 'no value' // 0 会被当作 '没有价值'

        if (fRescan) { // 若开启再扫描
            pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true); // 再扫描整个钱包交易
        }
    }

    return NullUniValue; // 成功返回空值
}

void ImportAddress(const CBitcoinAddress& address, const string& strLabel); // 导入地址到钱包
void ImportScript(const CScript& script, const string& strLabel, bool isRedeemScript) // 导入脚本
{
    if (!isRedeemScript && ::IsMine(*pwalletMain, script) == ISMINE_SPENDABLE) // P2SH 类型 且 是自己的脚本
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");

    pwalletMain->MarkDirty(); // 标记钱包已改变

    if (!pwalletMain->HaveWatchOnly(script) && !pwalletMain->AddWatchOnly(script)) // 若 watch-only 集合中没有指定脚本，则添加该脚本到 watch-only 脚本集合
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");

    if (isRedeemScript) { // 若为赎回脚本
        if (!pwalletMain->HaveCScript(script) && !pwalletMain->AddCScript(script))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding p2sh redeemScript to wallet");
        ImportAddress(CBitcoinAddress(CScriptID(script)), strLabel); // 导入地址及关联账户
    }
}

void ImportAddress(const CBitcoinAddress& address, const string& strLabel)
{
    CScript script = GetScriptForDestination(address.Get()); // 通过脚本索引获取脚本
    ImportScript(script, strLabel, false); // 导入脚本
    // add to address book or update label // 添加到地址簿或更新账户
    if (address.IsValid()) // 若该地址有效
        pwalletMain->SetAddressBook(address.Get(), strLabel, "receive"); // 添加地址及关联账户、用途到地址簿
}

UniValue importaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 4) // 参数最少为 1 个，最多 4 个
        throw runtime_error( // 命令参数反馈
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


    string strLabel = ""; // 账户名，默认为 ""
    if (params.size() > 1)
        strLabel = params[1].get_str(); // 获取账户名或脚本

    // Whether to perform rescan after import // 在导入后是否执行再扫描
    bool fRescan = true; // 再扫描选项，默认开启
    if (params.size() > 2)
        fRescan = params[2].get_bool(); // 获取再扫描设置

    if (fRescan && fPruneMode) // 再扫描和修剪模式不能兼容
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    // Whether to import a p2sh version, too
    bool fP2SH = false; // 是否也导入 p2sh 版本的脚本
    if (params.size() > 3)
        fP2SH = params[3].get_bool(); // 获取选项设置

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    CBitcoinAddress address(params[0].get_str()); // 初始化比特币地址
    if (address.IsValid()) { // 若地址有效
        if (fP2SH) // 还开启了 P2SH 标志
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot use the p2sh flag with an address - use a script instead"); // 抛出异常
        ImportAddress(address, strLabel); // 导入地址及其关联账户
    } else if (IsHex(params[0].get_str())) { // 若地址无效，表明是脚本
        std::vector<unsigned char> data(ParseHex(params[0].get_str())); // 把脚本放入 vector 容器中
        ImportScript(CScript(data.begin(), data.end()), strLabel, fP2SH); // 导入脚本
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address or script");
    }

    if (fRescan) // 若再扫描开启
    {
        pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true); // 再扫描钱包交易
        pwalletMain->ReacceptWalletTransactions(); // 把交易放入内存池
    }

    return NullUniValue; // 返回空值
}

UniValue importpubkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 4) // 参数最少 1 个，最多 3 个，这里错了
        throw runtime_error( // 命令帮助反馈
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


    string strLabel = ""; // 帐户名，默认为 ""
    if (params.size() > 1)
        strLabel = params[1].get_str(); // 获取指定的帐户名

    // Whether to perform rescan after import // 在导入之后是否执行再扫描
    bool fRescan = true; // 再扫描选项，默认开启
    if (params.size() > 2)
        fRescan = params[2].get_bool(); // 获取再扫描设置

    if (fRescan && fPruneMode) // 再扫描与修剪模式步兼容
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");

    if (!IsHex(params[0].get_str())) // 公钥必须为 16 进制
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey must be a hex string");
    std::vector<unsigned char> data(ParseHex(params[0].get_str()));
    CPubKey pubKey(data.begin(), data.end()); // 初始化公钥
    if (!pubKey.IsFullyValid()) // 该公钥是否有效
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey is not a valid public key");

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    ImportAddress(CBitcoinAddress(pubKey.GetID()), strLabel); // 导入地址及关联账户
    ImportScript(GetScriptForRawPubKey(pubKey), strLabel, false); // 导入脚本

    if (fRescan) // 若开启了再扫描
    {
        pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true); // 再扫描钱包交易
        pwalletMain->ReacceptWalletTransactions(); // 把交易放入内存池
    }

    return NullUniValue; // 返回空值
}


UniValue importwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // 参数必须为 1 个
        throw runtime_error( // 命令帮助反馈
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

    if (fPruneMode) // 导入钱包在修剪模式下无效
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing wallets is disabled in pruned mode");

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    EnsureWalletIsUnlocked(); // 确保钱包此时未加密

    ifstream file; // 文件输入流对象
    file.open(params[0].get_str().c_str(), std::ios::in | std::ios::ate); // 打开指定文件并立刻定位到文件流结尾
    if (!file.is_open()) // 判断文件的打开状态
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    int64_t nTimeBegin = chainActive.Tip()->GetBlockTime(); // 获取最佳区块创建时间

    bool fGood = true;

    int64_t nFilesize = std::max((int64_t)1, (int64_t)file.tellg()); // 通过文件指针的位置获取文件大小，用于显示加载进度
    file.seekg(0, file.beg); // 文件指针定位到文件流开头

    pwalletMain->ShowProgress(_("Importing..."), 0); // show progress dialog in GUI
    while (file.good()) { // 文件流状态正常时
        pwalletMain->ShowProgress("", std::max(1, std::min(99, (int)(((double)file.tellg() / (double)nFilesize) * 100))));
        std::string line;
        std::getline(file, line); // 读取一行
        if (line.empty() || line[0] == '#') // 若该行为空 或 行首字符为 '#'
            continue; // 跳过空行 或 注释行

        std::vector<std::string> vstr;
        boost::split(vstr, line, boost::is_any_of(" ")); // 按空格 " " 分隔字符串
        if (vstr.size() < 2) // 字符串个数不能低于 2 个
            continue;
        CBitcoinSecret vchSecret;
        if (!vchSecret.SetString(vstr[0])) // Base58 编码的私钥
            continue;
        CKey key = vchSecret.GetKey(); // 获取私钥
        CPubKey pubkey = key.GetPubKey(); // 计算得到公钥
        assert(key.VerifyPubKey(pubkey)); // 验证公钥私钥是否匹配
        CKeyID keyid = pubkey.GetID(); // 获取公钥索引作为密钥索引
        if (pwalletMain->HaveKey(keyid)) { // 检查密钥索引对应密钥是否存在
            LogPrintf("Skipping import of %s (key already present)\n", CBitcoinAddress(keyid).ToString());
            continue;
        }
        int64_t nTime = DecodeDumpTime(vstr[1]); // 获取并编码时间
        std::string strLabel; // 保存 label 标签的值，账户名
        bool fLabel = true; // 账户标志，默认为 true
        for (unsigned int nStr = 2; nStr < vstr.size(); nStr++) { // 第三个参数，标签类别
            if (boost::algorithm::starts_with(vstr[nStr], "#")) // 没有标签，直接跳出
                break;
            if (vstr[nStr] == "change=1")
                fLabel = false;
            if (vstr[nStr] == "reserve=1")
                fLabel = false;
            if (boost::algorithm::starts_with(vstr[nStr], "label=")) {
                strLabel = DecodeDumpString(vstr[nStr].substr(6)); // 从下标为 6 的字符开始截取字串
                fLabel = true; // 账户标志置为 true
            }
        }
        LogPrintf("Importing %s...\n", CBitcoinAddress(keyid).ToString()); // 记录导入公钥地址
        if (!pwalletMain->AddKeyPubKey(key, pubkey)) { // 把公私对添加到钱包
            fGood = false;
            continue;
        }
        pwalletMain->mapKeyMetadata[keyid].nCreateTime = nTime; // 导入私钥创建时间
        if (fLabel) // 若该密钥有所属账户
            pwalletMain->SetAddressBook(keyid, strLabel, "receive"); // 设置到地址簿并设置其所属账户名
        nTimeBegin = std::min(nTimeBegin, nTime);
    }
    file.close(); // 关闭文件输入流
    pwalletMain->ShowProgress("", 100); // hide progress dialog in GUI

    CBlockIndex *pindex = chainActive.Tip(); // 获取链尖区块索引指针
    while (pindex && pindex->pprev && pindex->GetBlockTime() > nTimeBegin - 7200)
        pindex = pindex->pprev; // 寻找时间相差 2h 的块

    if (!pwalletMain->nTimeFirstKey || nTimeBegin < pwalletMain->nTimeFirstKey)
        pwalletMain->nTimeFirstKey = nTimeBegin;

    LogPrintf("Rescanning last %i blocks\n", chainActive.Height() - pindex->nHeight + 1);
    pwalletMain->ScanForWalletTransactions(pindex); // 从某个块开始扫描块上的交易
    pwalletMain->MarkDirty(); // 标记钱包已改变

    if (!fGood) // 某个密钥添加到钱包失败
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");

    return NullUniValue; // 返回空值
}

UniValue dumpprivkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // 参数必须为 1 个
        throw runtime_error( // 命令帮助反馈
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

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    EnsureWalletIsUnlocked(); // 确保钱包当前解锁（为加密或加密了但处于解密状态）

    string strAddress = params[0].get_str(); // 获取指定的公钥地址
    CBitcoinAddress address;
    if (!address.SetString(strAddress)) // 初始化一个比特币地址对象
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    CKeyID keyID;
    if (!address.GetKeyID(keyID)) // 获取该地址的索引
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CKey vchSecret;
    if (!pwalletMain->GetKey(keyID, vchSecret)) // 通过索引获取对应的私钥
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    return CBitcoinSecret(vchSecret).ToString(); // 对私钥进行 Base58 编码并返回结果
}


UniValue dumpwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) // 确保当前钱包可用
        return NullUniValue;
    
    if (fHelp || params.size() != 1) // 参数必须为 1 个
        throw runtime_error( // 命令帮助反馈
            "dumpwallet \"filename\"\n"
            "\nDumps all wallet keys in a human-readable format.\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The filename\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpwallet", "\"test\"")
            + HelpExampleRpc("dumpwallet", "\"test\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet); // 钱包上锁

    EnsureWalletIsUnlocked(); // 确保当前钱包未加密

    ofstream file; // 文件输出流对象
    file.open(params[0].get_str().c_str()); // 打开指定文件
    if (!file.is_open()) // 检测打开文件状态
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    std::map<CKeyID, int64_t> mapKeyBirth; // 密钥创建时间
    std::set<CKeyID> setKeyPool; // 密钥池集合
    pwalletMain->GetKeyBirthTimes(mapKeyBirth); // 获取钱包密钥创建时间
    pwalletMain->GetAllReserveKeys(setKeyPool); // 获取所有预创建的密钥

    // sort time/key pairs
    std::vector<std::pair<int64_t, CKeyID> > vKeyBirth; // 密钥创建时间映射列表
    for (std::map<CKeyID, int64_t>::const_iterator it = mapKeyBirth.begin(); it != mapKeyBirth.end(); it++) {
        vKeyBirth.push_back(std::make_pair(it->second, it->first)); // 把 map 内的数据导入 vector
    }
    mapKeyBirth.clear(); // 清空 map
    std::sort(vKeyBirth.begin(), vKeyBirth.end()); // 对该列表按创建时间进行排序，默认升序

    // produce output
    file << strprintf("# Wallet dump created by Bitcoin %s (%s)\n", CLIENT_BUILD, CLIENT_DATE); // 客户端版本
    file << strprintf("# * Created on %s\n", EncodeDumpTime(GetTime())); // 当前时间
    file << strprintf("# * Best block at time of backup was %i (%s),\n", chainActive.Height(), chainActive.Tip()->GetBlockHash().ToString()); // 最佳块的高度和哈希
    file << strprintf("#   mined on %s\n", EncodeDumpTime(chainActive.Tip()->GetBlockTime())); // 最佳块产生的时间
    file << "\n";
    for (std::vector<std::pair<int64_t, CKeyID> >::const_iterator it = vKeyBirth.begin(); it != vKeyBirth.end(); it++) {
        const CKeyID &keyid = it->second; // 获取密钥索引
        std::string strTime = EncodeDumpTime(it->first); // 编码时间，按一定的格式输出
        std::string strAddr = CBitcoinAddress(keyid).ToString(); // 获取公钥地址
        CKey key; // 私钥
        if (pwalletMain->GetKey(keyid, key)) { // 通过密钥索引获取对应私钥
            if (pwalletMain->mapAddressBook.count(keyid)) { // 密钥索引存在于地址簿映射列表
                file << strprintf("%s %s label=%s # addr=%s\n", CBitcoinSecret(key).ToString(), strTime, EncodeDumpString(pwalletMain->mapAddressBook[keyid].name), strAddr); // label=
            } else if (setKeyPool.count(keyid)) { // 密钥索引存在于密钥池集合
                file << strprintf("%s %s reserve=1 # addr=%s\n", CBitcoinSecret(key).ToString(), strTime, strAddr); // reserve=1
            } else { // 其他类型
                file << strprintf("%s %s change=1 # addr=%s\n", CBitcoinSecret(key).ToString(), strTime, strAddr); // change=1
            }
        }
    }
    file << "\n";
    file << "# End of dump\n"; // 导出结束
    file.close(); // 关闭文件输出流
    return NullUniValue; // 返回空值
}
