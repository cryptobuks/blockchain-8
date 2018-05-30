// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "coins.h"
#include "consensus/validation.h"
#include "main.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "rpcserver.h"
#include "streams.h"
#include "sync.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"

#include <stdint.h>

#include <univalue.h>

using namespace std;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);
void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex);

double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty, // 最小难度倍数的浮点数
    // minimum difficulty = 1.0. // 最小难度 = 1.0
    if (blockindex == NULL)
    {
        if (chainActive.Tip() == NULL) // 链尖为空
            return 1.0; // 返回最小难度
        else
            blockindex = chainActive.Tip(); // 获取链尖区块索引
    }

    int nShift = (blockindex->nBits >> 24) & 0xff; // 获取 nBits 的高 8 位 2 进制

    double dDiff = // main and testnet (0x1d00ffff) or regtest (0x207fffff) 0x1e0ffff0 (dash)
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff); // 计算难度

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) // main and testnet (0x1d, 29) or regtest (0x20, 32)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff; // 返回难度
}

UniValue blockheaderToJSON(const CBlockIndex* blockindex)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", blockindex->GetBlockHash().GetHex())); // 区块哈希
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->nHeight + 1; // 计算确认数
    result.push_back(Pair("confirmations", confirmations)); // 确认数
    result.push_back(Pair("height", blockindex->nHeight)); // 区块链高度
    result.push_back(Pair("version", blockindex->nVersion)); // 区块版本号
    result.push_back(Pair("merkleroot", blockindex->hashMerkleRoot.GetHex())); // 默克树根
    result.push_back(Pair("time", (int64_t)blockindex->nTime)); // 区块创建时间
    result.push_back(Pair("mediantime", (int64_t)blockindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", (uint64_t)blockindex->nNonce)); // 随机数
    result.push_back(Pair("bits", strprintf("%08x", blockindex->nBits))); // 难度对应值
    result.push_back(Pair("difficulty", GetDifficulty(blockindex))); // 难度
    result.push_back(Pair("chainwork", blockindex->nChainWork.GetHex())); // 工作量

    if (blockindex->pprev) // 上一个区块的哈希
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext) // 下一个区块的哈希
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));
    return result;
}

UniValue blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool txDetails = false)
{
    UniValue result(UniValue::VOBJ); // 创建对象类型的返回结果
    result.push_back(Pair("hash", block.GetHash().GetHex())); // 先加入区块的哈希（16 进制形式）
    int confirmations = -1; // 记录该区块的确认数
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex)) // 若该区块在链上
        confirmations = chainActive.Height() - blockindex->nHeight + 1; // 计算确认数，注：刚上链的确认数为 1
    result.push_back(Pair("confirmations", confirmations)); // 加入确认数
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION))); // 区块大小（单位字节）
    result.push_back(Pair("height", blockindex->nHeight)); // 区块高度
    result.push_back(Pair("version", block.nVersion)); // 区块版本
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex())); // 默克树根
    UniValue txs(UniValue::VARR); // 数组类型的交易对象
    BOOST_FOREACH(const CTransaction&tx, block.vtx)
    { // 遍历交易列表
        if(txDetails) // false
        { // 交易细节
            UniValue objTx(UniValue::VOBJ);
            TxToJSON(tx, uint256(), objTx); // 把交易信息转换为 JSON 格式输入到 objTx
            txs.push_back(objTx);
        }
        else // 加入交易哈希
            txs.push_back(tx.GetHash().GetHex());
    }
    result.push_back(Pair("tx", txs)); // 交易集
    result.push_back(Pair("time", block.GetBlockTime())); // 获取区块创建时间
    result.push_back(Pair("mediantime", (int64_t)blockindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", (uint64_t)block.nNonce)); // 随机数
    result.push_back(Pair("bits", strprintf("%08x", block.nBits))); // 难度对应值
    result.push_back(Pair("difficulty", GetDifficulty(blockindex))); // 难度
    result.push_back(Pair("chainwork", blockindex->nChainWork.GetHex())); // 链工作量

    if (blockindex->pprev) // 如果有前一个区块
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex())); // 加入前一个区块的哈希
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext) // 如果后后一个区块
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex())); // 加入后一个区块的哈希
    return result; // 返回结果
}

UniValue getblockcount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // 没有参数
        throw runtime_error( // 帮助信息反馈
            "getblockcount\n"
            "\nReturns the number of blocks in the longest block chain.\n"
            "\nResult:\n"
            "n    (numeric) The current block count\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockcount", "")
            + HelpExampleRpc("getblockcount", "")
        );

    LOCK(cs_main);
    return chainActive.Height(); // 返回激活的链高度
}

UniValue getbestblockhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // 1.该命令没有参数
        throw runtime_error( // 命令帮助反馈
            "getbestblockhash\n"
            "\nReturns the hash of the best (tip) block in the longest block chain.\n"
            "\nResult\n"
            "\"hex\"      (string) the block hash hex encoded\n"
            "\nExamples\n"
            + HelpExampleCli("getbestblockhash", "")
            + HelpExampleRpc("getbestblockhash", "")
        );

    LOCK(cs_main);
    return chainActive.Tip()->GetBlockHash().GetHex(); // 2.返回激活链尖区块哈希的 16 进制
}

UniValue getdifficulty(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // 没有参数
        throw runtime_error( // 命令帮助反馈
            "getdifficulty\n"
            "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nResult:\n"
            "n.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nExamples:\n"
            + HelpExampleCli("getdifficulty", "")
            + HelpExampleRpc("getdifficulty", "")
        );

    LOCK(cs_main); // 上锁
    return GetDifficulty(); // 返回获取的难度值
}

UniValue mempoolToJSON(bool fVerbose = false)
{
    if (fVerbose)
    { // 打包交易详细信息
        LOCK(mempool.cs);
        UniValue o(UniValue::VOBJ);
        BOOST_FOREACH(const CTxMemPoolEntry& e, mempool.mapTx)
        { // 遍历获取交易池中的交易条目
            const uint256& hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);
            info.push_back(Pair("size", (int)e.GetTxSize())); // 交易大小
            info.push_back(Pair("fee", ValueFromAmount(e.GetFee()))); // 交易费
            info.push_back(Pair("modifiedfee", ValueFromAmount(e.GetModifiedFee()))); // 修改的交易费
            info.push_back(Pair("time", e.GetTime())); // 当前时间
            info.push_back(Pair("height", (int)e.GetHeight())); // 当前区块高度
            info.push_back(Pair("startingpriority", e.GetPriority(e.GetHeight()))); // 起始优先级（通过链高度）
            info.push_back(Pair("currentpriority", e.GetPriority(chainActive.Height()))); // 当前优先级
            info.push_back(Pair("descendantcount", e.GetCountWithDescendants())); // 后裔数量
            info.push_back(Pair("descendantsize", e.GetSizeWithDescendants())); // 后裔大小
            info.push_back(Pair("descendantfees", e.GetModFeesWithDescendants())); // 后裔费用
            const CTransaction& tx = e.GetTx();
            set<string> setDepends; // 交易输入的依赖
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                if (mempool.exists(txin.prevout.hash)) // 查询交易输入的输出哈希在内存池中是否存在
                    setDepends.insert(txin.prevout.hash.ToString()); // 加入依赖集合
            }

            UniValue depends(UniValue::VARR);
            BOOST_FOREACH(const string& dep, setDepends) // 构建依赖目标对象
            {
                depends.push_back(dep);
            }

            info.push_back(Pair("depends", depends)); // 加入交易依赖
            o.push_back(Pair(hash.ToString(), info)); // 交易索引 与 交易信息 配对
        }
        return o;
    }
    else
    { // 打包交易索引（哈希）
        vector<uint256> vtxid;
        mempool.queryHashes(vtxid); // 填充交易池中的交易哈希到 vtxid

        UniValue a(UniValue::VARR);
        BOOST_FOREACH(const uint256& hash, vtxid)
            a.push_back(hash.ToString());

        return a;
    }
}

UniValue getrawmempool(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1) // 参数至多为 1 个
        throw runtime_error( // 命令帮助反馈
            "getrawmempool ( verbose )\n"
            "\nReturns all transaction ids in memory pool as a json array of string transaction ids.\n"
            "\nArguments:\n"
            "1. verbose           (boolean, optional, default=false) true for a json object, false for array of transaction ids\n"
            "\nResult: (for verbose = false):\n"
            "[                     (json array of string)\n"
            "  \"transactionid\"     (string) The transaction id\n"
            "  ,...\n"
            "]\n"
            "\nResult: (for verbose = true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n"
            "    \"size\" : n,             (numeric) transaction size in bytes\n"
            "    \"fee\" : n,              (numeric) transaction fee in " + CURRENCY_UNIT + "\n"
            "    \"modifiedfee\" : n,      (numeric) transaction fee with fee deltas used for mining priority\n"
            "    \"time\" : n,             (numeric) local time transaction entered pool in seconds since 1 Jan 1970 GMT\n"
            "    \"height\" : n,           (numeric) block height when transaction entered pool\n"
            "    \"startingpriority\" : n, (numeric) priority when transaction entered pool\n"
            "    \"currentpriority\" : n,  (numeric) transaction priority now\n"
            "    \"descendantcount\" : n,  (numeric) number of in-mempool descendant transactions (including this one)\n"
            "    \"descendantsize\" : n,   (numeric) size of in-mempool descendants (including this one)\n"
            "    \"descendantfees\" : n,   (numeric) modified fees (see above) of in-mempool descendants (including this one)\n"
            "    \"depends\" : [           (array) unconfirmed transactions used as inputs for this transaction\n"
            "        \"transactionid\",    (string) parent transaction id\n"
            "       ... ]\n"
            "  }, ...\n"
            "}\n"
            "\nExamples\n"
            + HelpExampleCli("getrawmempool", "true")
            + HelpExampleRpc("getrawmempool", "true")
        );

    LOCK(cs_main); // 上锁

    bool fVerbose = false; // 详细标志，默认为 false
    if (params.size() > 0)
        fVerbose = params[0].get_bool(); // 获取详细参数

    return mempoolToJSON(fVerbose); // 把内存池交易打包为 JSON 格式并返回
}

UniValue getblockhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // 参数只有 1 个
        throw runtime_error( // 命令帮助反馈
            "getblockhash index\n"
            "\nReturns hash of block in best-block-chain at index provided.\n"
            "\nArguments:\n"
            "1. index         (numeric, required) The block index\n"
            "\nResult:\n"
            "\"hash\"         (string) The block hash\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockhash", "1000")
            + HelpExampleRpc("getblockhash", "1000")
        );

    LOCK(cs_main); // 上锁

    int nHeight = params[0].get_int(); // 获取指定的区块索引作为区块链高度
    if (nHeight < 0 || nHeight > chainActive.Height()) // 检测指定高度是否在该区块链高度范围内
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    CBlockIndex* pblockindex = chainActive[nHeight]; // 获取激活链对应高度的区块索引
    return pblockindex->GetBlockHash().GetHex(); // 获取该索引对应区块哈希，转换为 16 进制并返回
}

UniValue getblockheader(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) // 参数至少为 1 个（区块哈希），至多 2 个
        throw runtime_error( // 命令帮助反馈
            "getblockheader \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.\n"
            "If verbose is true, returns an Object with information about blockheader <hash>.\n"
            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"
            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\",      (string) The hash of the next block\n"
            "  \"chainwork\" : \"0000...1f3\"     (string) Expected number of hashes required to produce the current chain (in hex)\n"
            "}\n"
            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash'.\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
        );

    LOCK(cs_main); // 上锁

    std::string strHash = params[0].get_str(); // 获取区块哈希字符串
    uint256 hash(uint256S(strHash)); // 创建 uint256 局部对象

    bool fVerbose = true; // 详细信息标志，默认为 true
    if (params.size() > 1)
        fVerbose = params[1].get_bool(); // 获取是否显示详细信息

    if (mapBlockIndex.count(hash) == 0) // 判断哈希对应的区块是否存在于区块索引映射
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlockIndex* pblockindex = mapBlockIndex[hash]; // 获取指定哈希的区块索引

    if (!fVerbose) // false
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION); // 序列化
        ssBlock << pblockindex->GetBlockHeader(); // 通过区块索引获取并导入区块头数据
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end()); // 16 进制化
        return strHex; // 返回
    }

    return blockheaderToJSON(pblockindex); // 封装区块头信息为 JSON 格式并返回
}

UniValue getblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) // 1.必须有 1 个参数（谋区块的哈希），最多 2 个
        throw runtime_error( // 命令帮助反馈
            "getblock \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
            "If verbose is true, returns an Object with information about block <hash>.\n"
            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"
            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"size\" : n,            (numeric) The block size\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"tx\" : [               (array of string) The transaction ids\n"
            "     \"transactionid\"     (string) The transaction id\n"
            "     ,...\n"
            "  ],\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"chainwork\" : \"xxxx\",  (string) Expected number of hashes required to produce the chain up to this block (in hex)\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\"       (string) The hash of the next block\n"
            "}\n"
            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash'.\n"
            "\nExamples:\n"
            + HelpExampleCli("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
        );

    LOCK(cs_main);

    std::string strHash = params[0].get_str(); // 2.把参数转换为字符串
    uint256 hash(uint256S(strHash)); // 包装成 uint256 对象

    bool fVerbose = true; // 3.详细标志，默认为 true
    if (params.size() > 1) // 若有第 2 个参数
        fVerbose = params[1].get_bool(); // 获取 verbose 的值（布尔型）

    if (mapBlockIndex.count(hash) == 0) // 4.检查指定哈希是否在区块索引映射中
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block; // 创建一个局部的区块对象
    CBlockIndex* pblockindex = mapBlockIndex[hash]; // 获取指定哈希对应的区块索引指针

    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0) // 5.区块文件未被修剪过 或 区块状态为在区块文件中为完整区块 或 区块索引中的交易号为 0
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Block not available (pruned data)");

    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) // 6.从磁盘上的文件中读取区块信息
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    if (!fVerbose) // 7.false
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION); // 序列化数据
        ssBlock << block; // 导入区块数据
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end()); // 16 进制化
        return strHex; // 返回
    }

    return blockToJSON(block, pblockindex); // 8.打包区块信息为 JSON 格式并返回
}

UniValue gettxoutsetinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "gettxoutsetinfo\n"
            "\nReturns statistics about the unspent transaction output set.\n"
            "Note this call may take some time.\n"
            "\nResult:\n"
            "{\n"
            "  \"height\":n,     (numeric) The current block height (index)\n"
            "  \"bestblock\": \"hex\",   (string) the best block hash hex\n"
            "  \"transactions\": n,      (numeric) The number of transactions\n"
            "  \"txouts\": n,            (numeric) The number of output transactions\n"
            "  \"bytes_serialized\": n,  (numeric) The serialized size\n"
            "  \"hash_serialized\": \"hash\",   (string) The serialized hash\n"
            "  \"total_amount\": x.xxx          (numeric) The total amount\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("gettxoutsetinfo", "")
            + HelpExampleRpc("gettxoutsetinfo", "")
        );

    UniValue ret(UniValue::VOBJ);

    CCoinsStats stats;
    FlushStateToDisk();
    if (pcoinsTip->GetStats(stats)) {
        ret.push_back(Pair("height", (int64_t)stats.nHeight));
        ret.push_back(Pair("bestblock", stats.hashBlock.GetHex()));
        ret.push_back(Pair("transactions", (int64_t)stats.nTransactions));
        ret.push_back(Pair("txouts", (int64_t)stats.nTransactionOutputs));
        ret.push_back(Pair("bytes_serialized", (int64_t)stats.nSerializedSize));
        ret.push_back(Pair("hash_serialized", stats.hashSerialized.GetHex()));
        ret.push_back(Pair("total_amount", ValueFromAmount(stats.nTotalAmount)));
    }
    return ret;
}

UniValue gettxout(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3) // 参数至少为 2 个（交易索引、交易输出号）
        throw runtime_error( // 帮助信息反馈
            "gettxout \"txid\" n ( includemempool )\n"
            "\nReturns details about an unspent transaction output.\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id\n"
            "2. n              (numeric, required) vout value\n"
            "3. includemempool  (boolean, optional) Whether to included the mem pool\n"
            "\nResult:\n"
            "{\n"
            "  \"bestblock\" : \"hash\",    (string) the block hash\n"
            "  \"confirmations\" : n,       (numeric) The number of confirmations\n"
            "  \"value\" : x.xxx,           (numeric) The transaction value in " + CURRENCY_UNIT + "\n"
            "  \"scriptPubKey\" : {         (json object)\n"
            "     \"asm\" : \"code\",       (string) \n"
            "     \"hex\" : \"hex\",        (string) \n"
            "     \"reqSigs\" : n,          (numeric) Number of required signatures\n"
            "     \"type\" : \"pubkeyhash\", (string) The type, eg pubkeyhash\n"
            "     \"addresses\" : [          (array of string) array of bitcoin addresses\n"
            "        \"bitcoinaddress\"     (string) bitcoin address\n"
            "        ,...\n"
            "     ]\n"
            "  },\n"
            "  \"version\" : n,            (numeric) The version\n"
            "  \"coinbase\" : true|false   (boolean) Coinbase or not\n"
            "}\n"

            "\nExamples:\n"
            "\nGet unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nView the details\n"
            + HelpExampleCli("gettxout", "\"txid\" 1") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("gettxout", "\"txid\", 1")
        );

    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ); // 目标对象

    std::string strHash = params[0].get_str(); // 获取交易索引哈希字符串
    uint256 hash(uint256S(strHash)); // 构建 uint256 字符串
    int n = params[1].get_int(); // 获取交易输出号
    bool fMempool = true; // 内存池标志，默认为 true
    if (params.size() > 2)
        fMempool = params[2].get_bool(); // 获取指定的内存池标志

    CCoins coins; // 创建一个被修剪得交易版本对象（只包含元数据和交易输出）
    if (fMempool) {
        LOCK(mempool.cs);
        CCoinsViewMemPool view(pcoinsTip, mempool); // 传入内存池对象创建其引用查看对象
        if (!view.GetCoins(hash, coins))
            return NullUniValue;
        mempool.pruneSpent(hash, coins); // TODO: this should be done by the CCoinsViewMemPool
    } else {
        if (!pcoinsTip->GetCoins(hash, coins))
            return NullUniValue;
    }
    if (n<0 || (unsigned int)n>=coins.vout.size() || coins.vout[n].IsNull())
        return NullUniValue;

    BlockMap::iterator it = mapBlockIndex.find(pcoinsTip->GetBestBlock());
    CBlockIndex *pindex = it->second;
    ret.push_back(Pair("bestblock", pindex->GetBlockHash().GetHex()));
    if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
        ret.push_back(Pair("confirmations", 0));
    else
        ret.push_back(Pair("confirmations", pindex->nHeight - coins.nHeight + 1));
    ret.push_back(Pair("value", ValueFromAmount(coins.vout[n].nValue)));
    UniValue o(UniValue::VOBJ);
    ScriptPubKeyToJSON(coins.vout[n].scriptPubKey, o, true);
    ret.push_back(Pair("scriptPubKey", o));
    ret.push_back(Pair("version", coins.nVersion));
    ret.push_back(Pair("coinbase", coins.fCoinBase));

    return ret;
}

UniValue verifychain(const UniValue& params, bool fHelp)
{
    int nCheckLevel = GetArg("-checklevel", DEFAULT_CHECKLEVEL);
    int nCheckDepth = GetArg("-checkblocks", DEFAULT_CHECKBLOCKS);
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "verifychain ( checklevel numblocks )\n"
            "\nVerifies blockchain database.\n"
            "\nArguments:\n"
            "1. checklevel   (numeric, optional, 0-4, default=" + strprintf("%d", nCheckLevel) + ") How thorough the block verification is.\n"
            "2. numblocks    (numeric, optional, default=" + strprintf("%d", nCheckDepth) + ", 0=all) The number of blocks to check.\n"
            "\nResult:\n"
            "true|false       (boolean) Verified or not\n"
            "\nExamples:\n"
            + HelpExampleCli("verifychain", "")
            + HelpExampleRpc("verifychain", "")
        );

    LOCK(cs_main);

    if (params.size() > 0)
        nCheckLevel = params[0].get_int();
    if (params.size() > 1)
        nCheckDepth = params[1].get_int();

    return CVerifyDB().VerifyDB(Params(), pcoinsTip, nCheckLevel, nCheckDepth);
}

/** Implementation of IsSuperMajority with better feedback */
static UniValue SoftForkMajorityDesc(int minVersion, CBlockIndex* pindex, int nRequired, const Consensus::Params& consensusParams)
{
    int nFound = 0;
    CBlockIndex* pstart = pindex;
    for (int i = 0; i < consensusParams.nMajorityWindow && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }

    UniValue rv(UniValue::VOBJ);
    rv.push_back(Pair("status", nFound >= nRequired));
    rv.push_back(Pair("found", nFound));
    rv.push_back(Pair("required", nRequired));
    rv.push_back(Pair("window", consensusParams.nMajorityWindow));
    return rv;
}

static UniValue SoftForkDesc(const std::string &name, int version, CBlockIndex* pindex, const Consensus::Params& consensusParams)
{
    UniValue rv(UniValue::VOBJ);
    rv.push_back(Pair("id", name));
    rv.push_back(Pair("version", version));
    rv.push_back(Pair("enforce", SoftForkMajorityDesc(version, pindex, consensusParams.nMajorityEnforceBlockUpgrade, consensusParams)));
    rv.push_back(Pair("reject", SoftForkMajorityDesc(version, pindex, consensusParams.nMajorityRejectBlockOutdated, consensusParams)));
    return rv;
}

static UniValue BIP9SoftForkDesc(const std::string& name, const Consensus::Params& consensusParams, Consensus::DeploymentPos id)
{
    UniValue rv(UniValue::VOBJ);
    rv.push_back(Pair("id", name));
    switch (VersionBitsTipState(consensusParams, id)) {
    case THRESHOLD_DEFINED: rv.push_back(Pair("status", "defined")); break;
    case THRESHOLD_STARTED: rv.push_back(Pair("status", "started")); break;
    case THRESHOLD_LOCKED_IN: rv.push_back(Pair("status", "locked_in")); break;
    case THRESHOLD_ACTIVE: rv.push_back(Pair("status", "active")); break;
    case THRESHOLD_FAILED: rv.push_back(Pair("status", "failed")); break;
    }
    return rv;
}

UniValue getblockchaininfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // 该命令没有参数
        throw runtime_error( // 帮助信息反馈
            "getblockchaininfo\n"
            "Returns an object containing various state info regarding block chain processing.\n"
            "\nResult:\n"
            "{\n"
            "  \"chain\": \"xxxx\",        (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "  \"blocks\": xxxxxx,         (numeric) the current number of blocks processed in the server\n"
            "  \"headers\": xxxxxx,        (numeric) the current number of headers we have validated\n"
            "  \"bestblockhash\": \"...\", (string) the hash of the currently best block\n"
            "  \"difficulty\": xxxxxx,     (numeric) the current difficulty\n"
            "  \"mediantime\": xxxxxx,     (numeric) median time for the current best block\n"
            "  \"verificationprogress\": xxxx, (numeric) estimate of verification progress [0..1]\n"
            "  \"chainwork\": \"xxxx\"     (string) total amount of work in active chain, in hexadecimal\n"
            "  \"pruned\": xx,             (boolean) if the blocks are subject to pruning\n"
            "  \"pruneheight\": xxxxxx,    (numeric) heighest block available\n"
            "  \"softforks\": [            (array) status of softforks in progress\n"
            "     {\n"
            "        \"id\": \"xxxx\",        (string) name of softfork\n"
            "        \"version\": xx,         (numeric) block version\n"
            "        \"enforce\": {           (object) progress toward enforcing the softfork rules for new-version blocks\n"
            "           \"status\": xx,       (boolean) true if threshold reached\n"
            "           \"found\": xx,        (numeric) number of blocks with the new version found\n"
            "           \"required\": xx,     (numeric) number of blocks required to trigger\n"
            "           \"window\": xx,       (numeric) maximum size of examined window of recent blocks\n"
            "        },\n"
            "        \"reject\": { ... }      (object) progress toward rejecting pre-softfork blocks (same fields as \"enforce\")\n"
            "     }, ...\n"
            "  ],\n"
            "  \"bip9_softforks\": [       (array) status of BIP9 softforks in progress\n"
            "     {\n"
            "        \"id\": \"xxxx\",        (string) name of the softfork\n"
            "        \"status\": \"xxxx\",    (string) one of \"defined\", \"started\", \"lockedin\", \"active\", \"failed\"\n"
            "     }\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockchaininfo", "")
            + HelpExampleRpc("getblockchaininfo", "")
        );

    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ); // 构造一个目标对象
    obj.push_back(Pair("chain",                 Params().NetworkIDString())); // 网络 ID，主网 或 测试网
    obj.push_back(Pair("blocks",                (int)chainActive.Height())); // 当前区块高度
    obj.push_back(Pair("headers",               pindexBestHeader ? pindexBestHeader->nHeight : -1)); // 当前最佳区块头高度，同区块高度
    obj.push_back(Pair("bestblockhash",         chainActive.Tip()->GetBlockHash().GetHex())); // 最佳区块哈希（16 进制）
    obj.push_back(Pair("difficulty",            (double)GetDifficulty())); // 挖矿难度
    obj.push_back(Pair("mediantime",            (int64_t)chainActive.Tip()->GetMedianTimePast())); // 当前时间
    obj.push_back(Pair("verificationprogress",  Checkpoints::GuessVerificationProgress(Params().Checkpoints(), chainActive.Tip()))); // 验证进度，与检查点和链尖有关
    obj.push_back(Pair("chainwork",             chainActive.Tip()->nChainWork.GetHex())); // 当前的链工作量（16 进制）
    obj.push_back(Pair("pruned",                fPruneMode)); // 是否开启修剪模式

    const Consensus::Params& consensusParams = Params().GetConsensus();
    CBlockIndex* tip = chainActive.Tip();
    UniValue softforks(UniValue::VARR);
    UniValue bip9_softforks(UniValue::VARR);
    softforks.push_back(SoftForkDesc("bip34", 2, tip, consensusParams));
    softforks.push_back(SoftForkDesc("bip66", 3, tip, consensusParams));
    softforks.push_back(SoftForkDesc("bip65", 4, tip, consensusParams));
    bip9_softforks.push_back(BIP9SoftForkDesc("csv", consensusParams, Consensus::DEPLOYMENT_CSV));
    obj.push_back(Pair("softforks",             softforks)); // 软分叉
    obj.push_back(Pair("bip9_softforks", bip9_softforks)); // bip9_软分叉

    if (fPruneMode) // 若开启了修剪模式
    {
        CBlockIndex *block = chainActive.Tip();
        while (block && block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA))
            block = block->pprev;

        obj.push_back(Pair("pruneheight",        block->nHeight)); // 加入修剪到的高度
    }
    return obj; // 返回目标对象
}

/** Comparison function for sorting the getchaintips heads.  */ // 用于 getchaintips 函数排序区块头的比较器
struct CompareBlocksByHeight // 函数对象，通过高度比较区块
{
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare // 确保相同高度不同的块比较后不等
           equal. Use the pointers themselves to make a distinction. */ // 使用指针区分。

        if (a->nHeight != b->nHeight)
          return (a->nHeight > b->nHeight);

        return a < b;
    }
};

UniValue getchaintips(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // 没有参数
        throw runtime_error( // 命令帮助反馈
            "getchaintips\n"
            "Return information about all known tips in the block tree,"
            " including the main chain as well as orphaned branches.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"height\": xxxx,         (numeric) height of the chain tip\n"
            "    \"hash\": \"xxxx\",         (string) block hash of the tip\n"
            "    \"branchlen\": 0          (numeric) zero for main chain\n"
            "    \"status\": \"active\"      (string) \"active\" for the main chain\n"
            "  },\n"
            "  {\n"
            "    \"height\": xxxx,\n"
            "    \"hash\": \"xxxx\",\n"
            "    \"branchlen\": 1          (numeric) length of branch connecting the tip to the main chain\n"
            "    \"status\": \"xxxx\"        (string) status of the chain (active, valid-fork, valid-headers, headers-only, invalid)\n"
            "  }\n"
            "]\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid\n"
            "\nExamples:\n"
            + HelpExampleCli("getchaintips", "")
            + HelpExampleRpc("getchaintips", "")
        );

    LOCK(cs_main); // 上锁

    /* Build up a list of chain tips.  We start with the list of all // 构建链尖列表。
       known blocks, and successively remove blocks that appear as pprev
       of another block.  */ // 我们从已知块的列表开始，并连续移除另一个区块的 pprev 区块，以获取链尖区块索引。
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips; // 链尖区块索引集合
    BOOST_FOREACH(const PAIRTYPE(const uint256, CBlockIndex*)& item, mapBlockIndex) // 遍历区块索引映射
        setTips.insert(item.second); // 插入链尖索引集合
    BOOST_FOREACH(const PAIRTYPE(const uint256, CBlockIndex*)& item, mapBlockIndex) // 遍历区块索引映射
    {
        const CBlockIndex* pprev = item.second->pprev;
        if (pprev)
            setTips.erase(pprev); // 移除区块的前一个区块
    }

    // Always report the currently active tip. // 总是报告当前激活的链尖
    setTips.insert(chainActive.Tip()); // 插入当前激活链尖区块索引

    /* Construct the output array.  */ // 构建输出数组
    UniValue res(UniValue::VARR); // 创建数组类型的结果对象
    BOOST_FOREACH(const CBlockIndex* block, setTips) // 遍历链尖区块索引集合
    {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("height", block->nHeight)); // 链高度（区块索引）
        obj.push_back(Pair("hash", block->phashBlock->GetHex())); // 区块哈希

        const int branchLen = block->nHeight - chainActive.FindFork(block)->nHeight; // 计算分支长度
        obj.push_back(Pair("branchlen", branchLen));

        string status; // 链状态
        if (chainActive.Contains(block)) { // 检查当前激活链上是否存在该区块
            // This block is part of the currently active chain. // 该区块是当前激活链的一部分
            status = "active"; // 状态标记为激活
        } else if (block->nStatus & BLOCK_FAILED_MASK) { // 该块或其祖先之一的区块无效
            // This block or one of its ancestors is invalid.
            status = "invalid"; // 状态标记为无效
        } else if (block->nChainTx == 0) { // 该块无法连接，因为该块或其父块之一的完整区块数据丢失
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only"; // 状态表记为仅区块头
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) { // 该区块已完全验证，但不再是激活链的一部分
            // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized. // 可能曾是激活的区块，但被重组
            status = "valid-fork"; // 状态标记为验证分叉
        } else if (block->IsValid(BLOCK_VALID_TREE)) { // 该区块头有效，但它没有被验证。
            // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain. // 可能从来不是有效链的一部分。
            status = "valid-headers"; // 状态标记为验证头部
        } else {
            // No clue.
            status = "unknown";
        }
        obj.push_back(Pair("status", status));

        res.push_back(obj);
    }

    return res; // 返回结果数组
}

UniValue mempoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ); // 构造一个目标对象
    ret.push_back(Pair("size", (int64_t) mempool.size())); // 内存池当前大小
    ret.push_back(Pair("bytes", (int64_t) mempool.GetTotalTxSize())); // 内存池交易总大小
    ret.push_back(Pair("usage", (int64_t) mempool.DynamicMemoryUsage())); // 动态内存用量
    size_t maxmempool = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    ret.push_back(Pair("maxmempool", (int64_t) maxmempool)); // 内存池的大小
    ret.push_back(Pair("mempoolminfee", ValueFromAmount(mempool.GetMinFee(maxmempool).GetFeePerK()))); // 内存池最小费用

    return ret;
}

UniValue getmempoolinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // 没有参数
        throw runtime_error( // 命令帮助反馈
            "getmempoolinfo\n"
            "\nReturns details on the active state of the TX memory pool.\n"
            "\nResult:\n"
            "{\n"
            "  \"size\": xxxxx,               (numeric) Current tx count\n"
            "  \"bytes\": xxxxx,              (numeric) Sum of all tx sizes\n"
            "  \"usage\": xxxxx,              (numeric) Total memory usage for the mempool\n"
            "  \"maxmempool\": xxxxx,         (numeric) Maximum memory usage for the mempool\n"
            "  \"mempoolminfee\": xxxxx       (numeric) Minimum fee for tx to be accepted\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getmempoolinfo", "")
            + HelpExampleRpc("getmempoolinfo", "")
        );

    return mempoolInfoToJSON(); // 把交易内存池信息打包为 JSON 格式并返回
}

UniValue invalidateblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "invalidateblock \"hash\"\n"
            "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to mark as invalid\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("invalidateblock", "\"blockhash\"")
            + HelpExampleRpc("invalidateblock", "\"blockhash\"")
        );

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    CValidationState state;

    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        InvalidateBlock(state, Params().GetConsensus(), pblockindex);
    }

    if (state.IsValid()) {
        ActivateBestChain(state, Params());
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

UniValue reconsiderblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "reconsiderblock \"hash\"\n"
            "\nRemoves invalidity status of a block and its descendants, reconsider them for activation.\n"
            "This can be used to undo the effects of invalidateblock.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to reconsider\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("reconsiderblock", "\"blockhash\"")
            + HelpExampleRpc("reconsiderblock", "\"blockhash\"")
        );

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    CValidationState state;

    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        ReconsiderBlock(state, pblockindex);
    }

    if (state.IsValid()) {
        ActivateBestChain(state, Params());
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}
