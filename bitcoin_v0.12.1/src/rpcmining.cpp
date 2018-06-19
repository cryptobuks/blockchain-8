// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "main.h"
#include "miner.h"
#include "net.h"
#include "pow.h"
#include "rpcserver.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validationinterface.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp>
#include <boost/shared_ptr.hpp>

#include <univalue.h>

using namespace std;

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is nonpositive.
 * If 'height' is nonnegative, compute the estimate at the time when a given block was found.
 */ // 返回基于最新发现的块每秒的平均网络哈希，或若发现是非正则返回最新的难度改变。若高度非负，计算找到一个给定区块时的估计值
UniValue GetNetworkHashPS(int lookup, int height) { // 默认 (120, -1)
    CBlockIndex *pb = chainActive.Tip(); // 获取链尖区块索引

    if (height >= 0 && height < chainActive.Height()) // 若指定高度符合当前链高度范围
        pb = chainActive[height]; // 获取对应高度的区块索引

    if (pb == NULL || !pb->nHeight) // 索引为空 或 为创世区块索引
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup <= 0) // 若发现是 -1，则使用从上次难度改变后的区块
        lookup = pb->nHeight % Params().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight) // 若发现大于链高度，则设置为链高度
        lookup = pb->nHeight;

    CBlockIndex *pb0 = pb;
    int64_t minTime = pb0->GetBlockTime(); // 获取最小创建区块时间
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime); // 获取最大创建区块时间
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime) // 最小和最大不能相等
        return 0;

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork; // 区间首尾区块的工作量之差
    int64_t timeDiff = maxTime - minTime; // 时间差

    return workDiff.getdouble() / timeDiff; // 转换为浮点数求平均值并返回
}

UniValue getnetworkhashps(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2) // 参数个数最多为 2 个
        throw runtime_error( // 命令帮助反馈
            "getnetworkhashps ( blocks height )\n"
            "\nReturns the estimated network hashes per second based on the last n blocks.\n"
            "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
            "Pass in [height] to estimate the network speed at the time when a certain block was found.\n"
            "\nArguments:\n"
            "1. blocks     (numeric, optional, default=120) The number of blocks, or -1 for blocks since last difficulty change.\n"
            "2. height     (numeric, optional, default=-1) To estimate at the time of the given height.\n"
            "\nResult:\n"
            "x             (numeric) Hashes per second estimated\n"
            "\nExamples:\n"
            + HelpExampleCli("getnetworkhashps", "")
            + HelpExampleRpc("getnetworkhashps", "")
       );

    LOCK(cs_main);
    return GetNetworkHashPS(params.size() > 0 ? params[0].get_int() : 120, params.size() > 1 ? params[1].get_int() : -1); // 获取网络算力（哈希次数/秒）并返回
}

UniValue getgenerate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // 没有参数
        throw runtime_error( // 命令帮助反馈
            "getgenerate\n"
            "\nReturn if the server is set to generate coins or not. The default is false.\n"
            "It is set with the command line argument -gen (or " + std::string(BITCOIN_CONF_FILENAME) + " setting gen)\n"
            "It can also be set with the setgenerate call.\n"
            "\nResult\n"
            "true|false      (boolean) If the server is set to generate coins or not\n"
            "\nExamples:\n"
            + HelpExampleCli("getgenerate", "")
            + HelpExampleRpc("getgenerate", "")
        );

    LOCK(cs_main);
    return GetBoolArg("-gen", DEFAULT_GENERATE); // 获取 "-gen" 选项的值并返回
}

UniValue generate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1) // 1.参数只能为 1 个（要生成区块的个数）
        throw runtime_error( // 帮助信息反馈
            "generate numblocks\n"
            "\nMine blocks immediately (before the RPC call returns)\n"
            "\nNote: this function can only be used on the regtest network\n"
            "\nArguments:\n"
            "1. numblocks    (numeric, required) How many blocks are generated immediately.\n"
            "\nResult\n"
            "[ blockhashes ]     (array) hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks\n"
            + HelpExampleCli("generate", "11")
        );

    if (!Params().MineBlocksOnDemand()) // 2.检测网络，只有回归测试网返回 true
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "This method can only be used on regtest"); // 提示

    int nHeightStart = 0; // 产生块前的高度
    int nHeightEnd = 0; // 产生块后的高度
    int nHeight = 0; // 当前区块链高度
    int nGenerate = params[0].get_int(); // 3.获取要产生区块的数目

    boost::shared_ptr<CReserveScript> coinbaseScript; // 4.创建创币交易脚本
    GetMainSignals().ScriptForMining(coinbaseScript);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbaseScript) // 5.若密钥池耗尽，根本不会返回脚本。抓住它。
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    //throw an error if no script was provided
    if (coinbaseScript->reserveScript.empty()) // 6.如果脚本为空，未被提供，则抛出一个错误
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available (mining requires a wallet)");

    {   // Don't keep cs_main locked
        LOCK(cs_main); // 缩小加锁的范围
        nHeightStart = chainActive.Height(); // 7.获取当前激活链高度
        nHeight = nHeightStart; // 记录当前高度
        nHeightEnd = nHeightStart+nGenerate; // 得到产生指定块数后的高度
    }
    unsigned int nExtraNonce = 0;
    UniValue blockHashes(UniValue::VARR); // 数组类型的区块哈希对象
    while (nHeight < nHeightEnd)
    { // 8.循环产生指定数目的区块
        auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(Params(), coinbaseScript->reserveScript)); // 创建区块模板
        if (!pblocktemplate.get()) // 验证是否创建成功
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        CBlock *pblock = &pblocktemplate->block; // 获取区块指针
        {
            LOCK(cs_main);
            IncrementExtraNonce(pblock, chainActive.Tip(), nExtraNonce); // 增加额外的随机数
        }
        while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus())) { // 检测区块是否满足工作量证明
            // Yes, there is a chance every nonce could fail to satisfy the -regtest
            // target -- 1 in 2^(2^32). That ain't gonna happen. // 每个随机数都有可能无法满足 -regtest 目标值 -- 2^(2^32) 分之 1。这不会发生的。
            ++pblock->nNonce; // 区块头内随机数加 1
        }
        CValidationState state;
        if (!ProcessNewBlock(state, Params(), NULL, pblock, true, NULL))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
        ++nHeight; // 增加当前高度
        blockHashes.push_back(pblock->GetHash().GetHex()); // 追加区块哈希

        //mark script as important because it was used at least for one coinbase output
        coinbaseScript->KeepScript(); // 标记该脚本为重要，因为它至少用作一个创币输出
    }
    return blockHashes; // 9.返回产生所有区块的哈希
}

UniValue setgenerate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) // 参数至少为 1 个，至多为 2 个
        throw runtime_error( // 命令帮助反馈
            "setgenerate generate ( genproclimit )\n"
            "\nSet 'generate' true or false to turn generation on or off.\n"
            "Generation is limited to 'genproclimit' processors, -1 is unlimited.\n"
            "See the getgenerate call for the current setting.\n"
            "\nArguments:\n"
            "1. generate         (boolean, required) Set to true to turn on generation, off to turn off.\n"
            "2. genproclimit     (numeric, optional) Set the processor limit for when generation is on. Can be -1 for unlimited.\n"
            "\nExamples:\n"
            "\nSet the generation on with a limit of one processor\n"
            + HelpExampleCli("setgenerate", "true 1") +
            "\nCheck the setting\n"
            + HelpExampleCli("getgenerate", "") +
            "\nTurn off generation\n"
            + HelpExampleCli("setgenerate", "false") +
            "\nUsing json rpc\n"
            + HelpExampleRpc("setgenerate", "true, 1")
        );

    if (Params().MineBlocksOnDemand()) // 若是回归测试网络，此方法不适用，使用 "generate" 代替
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Use the generate method instead of setgenerate on this network");

    bool fGenerate = true; // 挖矿开关标志
    if (params.size() > 0)
        fGenerate = params[0].get_bool(); // 获取指定的挖矿状态

    int nGenProcLimit = GetArg("-genproclimit", DEFAULT_GENERATE_THREADS); // 初始化默认挖矿线程数
    if (params.size() > 1)
    {
        nGenProcLimit = params[1].get_int(); // 获取指定的挖矿线程数
        if (nGenProcLimit == 0) // 若指定线程数为 0
            fGenerate = false; // 关闭挖矿功能
    }

    mapArgs["-gen"] = (fGenerate ? "1" : "0"); // 改变挖矿选项的值
    mapArgs ["-genproclimit"] = itostr(nGenProcLimit); // 修改挖矿线程数
    GenerateBitcoins(fGenerate, nGenProcLimit, Params()); // 创建指定数量的挖矿线程

    return NullUniValue; // 返回空值
}

UniValue getmininginfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // 没有参数
        throw runtime_error( // 命令帮助反馈
            "getmininginfo\n"
            "\nReturns a json object containing mining-related information."
            "\nResult:\n"
            "{\n"
            "  \"blocks\": nnn,             (numeric) The current block\n"
            "  \"currentblocksize\": nnn,   (numeric) The last block size\n"
            "  \"currentblocktx\": nnn,     (numeric) The last block transaction\n"
            "  \"difficulty\": xxx.xxxxx    (numeric) The current difficulty\n"
            "  \"errors\": \"...\"          (string) Current errors\n"
            "  \"generate\": true|false     (boolean) If the generation is on or off (see getgenerate or setgenerate calls)\n"
            "  \"genproclimit\": n          (numeric) The processor limit for generation. -1 if no generation. (see getgenerate or setgenerate calls)\n"
            "  \"pooledtx\": n              (numeric) The size of the mem pool\n"
            "  \"testnet\": true|false      (boolean) If using testnet or not\n"
            "  \"chain\": \"xxxx\",         (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
        );


    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ); // 创建对象类型的返回结果
    obj.push_back(Pair("blocks",           (int)chainActive.Height())); // 加入激活的链高度
    obj.push_back(Pair("currentblocksize", (uint64_t)nLastBlockSize)); // 最新区块的大小
    obj.push_back(Pair("currentblocktx",   (uint64_t)nLastBlockTx)); // 最新区块的交易数
    obj.push_back(Pair("difficulty",       (double)GetDifficulty())); // 当前挖矿难度
    obj.push_back(Pair("errors",           GetWarnings("statusbar"))); // 错误
    obj.push_back(Pair("genproclimit",     (int)GetArg("-genproclimit", DEFAULT_GENERATE_THREADS))); // 矿工线程数
    obj.push_back(Pair("networkhashps",    getnetworkhashps(params, false))); // 全网算力
    obj.push_back(Pair("pooledtx",         (uint64_t)mempool.size())); // 交易内存池大小
    obj.push_back(Pair("testnet",          Params().TestnetToBeDeprecatedFieldRPC())); // 是否为测试网
    obj.push_back(Pair("chain",            Params().NetworkIDString())); // 链名
    obj.push_back(Pair("generate",         getgenerate(params, false))); // 挖矿状态
    return obj;
}


// NOTE: Unlike wallet RPC (which use BTC values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
UniValue prioritisetransaction(const UniValue& params, bool fHelp) // 注：与钱包 RPC （使用 BTC）不同，挖矿 RPC 使用 satoshi 作为单位
{
    if (fHelp || params.size() != 3) // 必须为 3 个参数
        throw runtime_error( // 命令帮助反馈
            "prioritisetransaction <txid> <priority delta> <fee delta>\n"
            "Accepts the transaction into mined blocks at a higher (or lower) priority\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id.\n"
            "2. priority delta (numeric, required) The priority to add or subtract.\n"
            "                  The transaction selection algorithm considers the tx as it would have a higher priority.\n"
            "                  (priority of a transaction is calculated: coinage * value_in_satoshis / txsize) \n"
            "3. fee delta      (numeric, required) The fee value (in satoshis) to add (or subtract, if negative).\n"
            "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
            "                  considers the transaction as it would have paid a higher (or lower) fee.\n"
            "\nResult\n"
            "true              (boolean) Returns true\n"
            "\nExamples:\n"
            + HelpExampleCli("prioritisetransaction", "\"txid\" 0.0 10000")
            + HelpExampleRpc("prioritisetransaction", "\"txid\", 0.0, 10000")
        );

    LOCK(cs_main);

    uint256 hash = ParseHashStr(params[0].get_str(), "txid"); // 获取指定的交易哈希并创建 uint256 对象
    CAmount nAmount = params[2].get_int64(); // 获取交易金额

    mempool.PrioritiseTransaction(hash, params[0].get_str(), params[1].get_real(), nAmount); // 调整指定交易优先级
    return true;
}


// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state) // 注：假设一个确定的结果；如果结果是不确定的，必须由调用方处理
{
    if (state.IsValid()) // 无效状态
        return NullUniValue; // 返回空

    std::string strRejectReason = state.GetRejectReason(); // 获取拒绝原因
    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
    if (state.IsInvalid()) // 状态无效
    {
        if (strRejectReason.empty()) // 拒绝原因为空
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?"; // 应该是不可能的
}

UniValue getblocktemplate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1) // 参数最多为 1 个
        throw runtime_error( // 命令帮助反馈
            "getblocktemplate ( \"jsonrequestobject\" )\n"
            "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
            "It returns data needed to construct a block to work on.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments:\n"
            "1. \"jsonrequestobject\"       (string, optional) A json object in the following spec\n"
            "     {\n"
            "       \"mode\":\"template\"    (string, optional) This must be set to \"template\" or omitted\n"
            "       \"capabilities\":[       (array, optional) A list of strings\n"
            "           \"support\"           (string) client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'\n"
            "           ,...\n"
            "         ]\n"
            "     }\n"
            "\n"

            "\nResult:\n"
            "{\n"
            "  \"version\" : n,                    (numeric) The block version\n"
            "  \"previousblockhash\" : \"xxxx\",    (string) The hash of current highest block\n"
            "  \"transactions\" : [                (array) contents of non-coinbase transactions that should be included in the next block\n"
            "      {\n"
            "         \"data\" : \"xxxx\",          (string) transaction data encoded in hexadecimal (byte-for-byte)\n"
            "         \"hash\" : \"xxxx\",          (string) hash/id encoded in little-endian hexadecimal\n"
            "         \"depends\" : [              (array) array of numbers \n"
            "             n                        (numeric) transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is\n"
            "             ,...\n"
            "         ],\n"
            "         \"fee\": n,                   (numeric) difference in value between transaction inputs and outputs (in Satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one\n"
            "         \"sigops\" : n,               (numeric) total number of SigOps, as counted for purposes of block limits; if key is not present, sigop count is unknown and clients MUST NOT assume there aren't any\n"
            "         \"required\" : true|false     (boolean) if provided and true, this transaction must be in the final block\n"
            "      }\n"
            "      ,...\n"
            "  ],\n"
            "  \"coinbaseaux\" : {                  (json object) data that should be included in the coinbase's scriptSig content\n"
            "      \"flags\" : \"flags\"            (string) \n"
            "  },\n"
            "  \"coinbasevalue\" : n,               (numeric) maximum allowable input to coinbase transaction, including the generation award and transaction fees (in Satoshis)\n"
            "  \"coinbasetxn\" : { ... },           (json object) information for coinbase transaction\n"
            "  \"target\" : \"xxxx\",               (string) The hash target\n"
            "  \"mintime\" : xxx,                   (numeric) The minimum timestamp appropriate for next block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mutable\" : [                      (array of string) list of ways the block template may be changed \n"
            "     \"value\"                         (string) A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'\n"
            "     ,...\n"
            "  ],\n"
            "  \"noncerange\" : \"00000000ffffffff\",   (string) A range of valid nonces\n"
            "  \"sigoplimit\" : n,                 (numeric) limit of sigops in blocks\n"
            "  \"sizelimit\" : n,                  (numeric) limit of block size\n"
            "  \"curtime\" : ttt,                  (numeric) current timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"bits\" : \"xxx\",                 (string) compressed target of next block\n"
            "  \"height\" : n                      (numeric) The height of the next block\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getblocktemplate", "")
            + HelpExampleRpc("getblocktemplate", "")
         );

    LOCK(cs_main); // 上锁

    std::string strMode = "template"; // 模式，默认为 "template"
    UniValue lpval = NullUniValue;
    if (params.size() > 0) // 指定了参数
    {
        const UniValue& oparam = params[0].get_obj(); // 获取参数对象
        const UniValue& modeval = find_value(oparam, "mode"); // 获取 "mode" 关键字对应的值
        if (modeval.isStr()) // 字符串类型
            strMode = modeval.get_str(); // 获取指定模式
        else if (modeval.isNull()) // 空
        {
            /* Do nothing */
        }
        else // 其它类型
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = find_value(oparam, "longpollid");

        if (strMode == "proposal") // "proposal" 模式
        {
            const UniValue& dataval = find_value(oparam, "data"); // 获取数据
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str())) // 解码 16 进制的区块
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash(); // 获取区块哈希
            BlockMap::iterator mi = mapBlockIndex.find(hash); // 在区块索引列表中查找指定区块
            if (mi != mapBlockIndex.end()) { // 若找到
                CBlockIndex *pindex = mi->second; // 获取指定区块索引指针
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) // 验证区块
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK) // 区块状态
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            } // 若未找到

            CBlockIndex* const pindexPrev = chainActive.Tip(); // 获取激活链尖
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash()) // 指定区块的前一个区块哈希是否为当前链尖区块
                return "inconclusive-not-best-prevblk";
            CValidationState state;
            TestBlockValidity(state, Params(), block, pindexPrev, false, true); // 测试区块有效性
            return BIP22ValidationResult(state); // 返回验证结果
        }
    }

    if (strMode != "template") // "template" 模式
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if (vNodes.empty()) // 已建立连接的节点列表非空
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Bitcoin is not connected!");

    if (IsInitialBlockDownload()) // 检查是否初始化块下载完成
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Bitcoin is downloading blocks...");

    static unsigned int nTransactionsUpdatedLast;

    if (!lpval.isNull())
    { // 等待响应，直到最佳块改变，或 1 分钟过去有更多的交易
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        boost::system_time checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            std::string lpstr = lpval.get_str();

            hashWatchedChain.SetHex(lpstr.substr(0, 64));
            nTransactionsUpdatedLastLP = atoi64(lpstr.substr(64));
        }
        else
        { // 注：规范没有对非字符串的 longpollip 指定行为，但这使测试更加容易
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = chainActive.Tip()->GetBlockHash(); // 获取链尖区块哈希
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast; // 最新的交易更新数量
        }

        // Release the wallet and main lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main); // 在等待时释放钱包和主锁
        {
            checktxtime = boost::get_system_time() + boost::posix_time::minutes(1); // 检查交易时间为 1 分钟后

            boost::unique_lock<boost::mutex> lock(csBestBlock); // 最佳区块上锁
            while (chainActive.Tip()->GetBlockHash() == hashWatchedChain && IsRPCRunning())
            { // 最佳区块未改变 且 RPC 服务开启
                if (!cvBlockChange.timed_wait(lock, checktxtime)) // 超时：检查交易用于更新
                {
                    // Timeout: Check transactions for update
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += boost::posix_time::seconds(10); // 检查时间加 10 秒
                }
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        if (!IsRPCRunning()) // 检查 RPC 服务是否开启
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    // Update block // 更新区块
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static CBlockTemplate* pblocktemplate;
    if (pindexPrev != chainActive.Tip() || // 最佳区块非空 或
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5)) // 交易内存池交易更新数量不等于最近交易更新数 且 当前时间过去 5 秒
    { // 清空 pindexPrev 以便将来调用创建一个新块，尽管这里可能会失败
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL; // 置空

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated(); // 获取当前交易更新数
        CBlockIndex* pindexPrevNew = chainActive.Tip(); // 获取链尖索引
        nStart = GetTime();

        // Create new block
        if(pblocktemplate) // 若区块模板已存在
        {
            delete pblocktemplate; // 先删除
            pblocktemplate = NULL; // 在置空
        }
        CScript scriptDummy = CScript() << OP_TRUE; // 脚本
        pblocktemplate = CreateNewBlock(Params(), scriptDummy); // 创建一个新块
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew; // 在我们直到创建新块成功后需要更新前一个区块的哈希
    }
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience

    // Update nTime
    UpdateTime(pblock, Params().GetConsensus(), pindexPrev); // 更新时间
    pblock->nNonce = 0; // 初始化随机数

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    map<uint256, int64_t> setTxIndex; // 交易索引映射列表
    int i = 0;
    BOOST_FOREACH (const CTransaction& tx, pblock->vtx) { // 遍历区块交易索引列表
        uint256 txHash = tx.GetHash(); // 获取交易哈希
        setTxIndex[txHash] = i++; // 加入交易索引映射列表

        if (tx.IsCoinBase()) // 若为创币交易
            continue; // 跳过

        UniValue entry(UniValue::VOBJ);

        entry.push_back(Pair("data", EncodeHexTx(tx))); // 编码 16 进制的交易

        entry.push_back(Pair("hash", txHash.GetHex())); // 获取 16 进制的交易索引

        UniValue deps(UniValue::VARR);
        BOOST_FOREACH (const CTxIn &in, tx.vin) // 遍历交易输入列表
        {
            if (setTxIndex.count(in.prevout.hash)) // 若前一笔交易输出在交易索引映射列表中
                deps.push_back(setTxIndex[in.prevout.hash]); // 加入依赖 json 数组
        }
        entry.push_back(Pair("depends", deps)); // 依赖交易

        int index_in_template = i - 1; // 当前交易的索引序号
        entry.push_back(Pair("fee", pblocktemplate->vTxFees[index_in_template])); // 交易费
        entry.push_back(Pair("sigops", pblocktemplate->vTxSigOps[index_in_template])); // 交易签名操作

        transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits); // 计算难度目标值

    static UniValue aMutable(UniValue::VARR);
    if (aMutable.empty())
    {
        aMutable.push_back("time"); // 时间
        aMutable.push_back("transactions"); // 交易
        aMutable.push_back("prevblock"); // 前一个区块
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("capabilities", aCaps)); // 功能
    result.push_back(Pair("version", pblock->nVersion)); // 区块版本
    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex())); // 前一个区块哈希
    result.push_back(Pair("transactions", transactions)); // 交易
    result.push_back(Pair("coinbaseaux", aux)); // coinbase aux
    result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue)); // 创币交易输出金额
    result.push_back(Pair("longpollid", chainActive.Tip()->GetBlockHash().GetHex() + i64tostr(nTransactionsUpdatedLast)));
    result.push_back(Pair("target", hashTarget.GetHex())); // 难度目标
    result.push_back(Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff")); // 随机数范围
    result.push_back(Pair("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS)); // 区块签名操作数量上限
    result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_SIZE)); // 区块大小上限
    result.push_back(Pair("curtime", pblock->GetBlockTime())); // 区块创建时间
    result.push_back(Pair("bits", strprintf("%08x", pblock->nBits))); // 难度
    result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1))); // 高度

    return result; // 返回结果
}

class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {};

protected:
    virtual void BlockChecked(const CBlock& block, const CValidationState& stateIn) {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    };
};

UniValue submitblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) // 参数只有 1 个
        throw runtime_error( // 命令帮助反馈
            "submitblock \"hexdata\" ( \"jsonparametersobject\" )\n"
            "\nAttempts to submit new block to network.\n"
            "The 'jsonparametersobject' parameter is currently ignored.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments\n"
            "1. \"hexdata\"    (string, required) the hex-encoded block data to submit\n"
            "2. \"jsonparametersobject\"     (string, optional) object of optional parameters\n"
            "    {\n"
            "      \"workid\" : \"id\"    (string, optional) if the server provided a workid, it MUST be included with submissions\n"
            "    }\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
        );

    CBlock block;
    if (!DecodeHexBlk(block, params[0].get_str())) // 解码 16 进制的区块数据
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    uint256 hash = block.GetHash(); // 获取区块哈希
    bool fBlockPresent = false;
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hash); // 通过区块索引得到该区块对应迭代器
        if (mi != mapBlockIndex.end()) { // 如果找到了
            CBlockIndex *pindex = mi->second; // 获取其区块索引
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                return "duplicate";
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return "duplicate-invalid";
            // Otherwise, we might only have the header - process the block before returning
            fBlockPresent = true;
        }
    }

    CValidationState state;
    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    bool fAccepted = ProcessNewBlock(state, Params(), NULL, &block, true, NULL);
    UnregisterValidationInterface(&sc);
    if (fBlockPresent)
    {
        if (fAccepted && !sc.found)
            return "duplicate-inconclusive";
        return "duplicate";
    }
    if (fAccepted)
    {
        if (!sc.found)
            return "inconclusive";
        state = sc.state;
    }
    return BIP22ValidationResult(state);
}

UniValue estimatefee(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // 参数必须为 1 个
        throw runtime_error( // 命令帮助反馈
            "estimatefee nblocks\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within nblocks blocks.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric)\n"
            "\nResult:\n"
            "n              (numeric) estimated fee-per-kilobyte\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatefee", "6")
            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)); // 参数类型检查

    int nBlocks = params[0].get_int(); // 获取指定的块数
    if (nBlocks < 1) // 块数最低为 1
        nBlocks = 1;

    CFeeRate feeRate = mempool.estimateFee(nBlocks); // 交易内存池预估交易费（根据区块数）
    if (feeRate == CFeeRate(0)) // 若交易费为 0
        return -1.0; // 返回 -1.0

    return ValueFromAmount(feeRate.GetFeePerK()); // 否则，格式化后返回预估交易费
}

UniValue estimatepriority(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // 参数必须为 1 个
        throw runtime_error( // 命令帮助反馈
            "estimatepriority nblocks\n"
            "\nEstimates the approximate priority a zero-fee transaction needs to begin\n"
            "confirmation within nblocks blocks.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric)\n"
            "\nResult:\n"
            "n              (numeric) estimated priority\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatepriority", "6")
            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)); // 检查参数类型

    int nBlocks = params[0].get_int(); // 获取指定区块数
    if (nBlocks < 1) // 区块至少为 1 块
        nBlocks = 1;

    return mempool.estimatePriority(nBlocks); // 在交易内存池中根据块数估算交易优先级，并返回
}

UniValue estimatesmartfee(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // 参数必须为 1 个
        throw runtime_error( // 命令帮助反馈
            "estimatesmartfee nblocks\n"
            "\nWARNING: This interface is unstable and may disappear or change!\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within nblocks blocks if possible and return the number of blocks\n"
            "for which the estimate is valid.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric)\n"
            "\nResult:\n"
            "{\n"
            "  \"feerate\" : x.x,     (numeric) estimate fee-per-kilobyte (in BTC)\n"
            "  \"blocks\" : n         (numeric) block number where estimate was found\n"
            "}\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
            "However it will not return a value below the mempool reject fee.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatesmartfee", "6")
            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)); // 参数类型检查

    int nBlocks = params[0].get_int(); // 获取指定的区块数

    UniValue result(UniValue::VOBJ);
    int answerFound; // 保存估计有效的块数
    CFeeRate feeRate = mempool.estimateSmartFee(nBlocks, &answerFound); // 智能估算交易费
    result.push_back(Pair("feerate", feeRate == CFeeRate(0) ? -1.0 : ValueFromAmount(feeRate.GetFeePerK()))); // 交易费
    result.push_back(Pair("blocks", answerFound)); // 有效的区块数
    return result; // 返回结果
}

UniValue estimatesmartpriority(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // 参数必须为 1 个
        throw runtime_error( // 命令帮助反馈
            "estimatesmartpriority nblocks\n"
            "\nWARNING: This interface is unstable and may disappear or change!\n"
            "\nEstimates the approximate priority a zero-fee transaction needs to begin\n"
            "confirmation within nblocks blocks if possible and return the number of blocks\n"
            "for which the estimate is valid.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric)\n"
            "\nResult:\n"
            "{\n"
            "  \"priority\" : x.x,    (numeric) estimated priority\n"
            "  \"blocks\" : n         (numeric) block number where estimate was found\n"
            "}\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
            "However if the mempool reject fee is set it will return 1e9 * MAX_MONEY.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatesmartpriority", "6")
            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)); // 检查参数类型

    int nBlocks = params[0].get_int(); // 获取指定的区块数

    UniValue result(UniValue::VOBJ);
    int answerFound; // 估计有效的区块数
    double priority = mempool.estimateSmartPriority(nBlocks, &answerFound); // 智能估算估算优先级并获取估算有效的区块数
    result.push_back(Pair("priority", priority)); // 交易优先级
    result.push_back(Pair("blocks", answerFound)); // 有效区块数
    return result; // 返回结果集
}
