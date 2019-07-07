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
    // Floating point number that is a multiple of the minimum difficulty, // ��С�Ѷȱ����ĸ�����
    // minimum difficulty = 1.0. // ��С�Ѷ� = 1.0
    if (blockindex == NULL)
    {
        if (chainActive.Tip() == NULL) // ����Ϊ��
            return 1.0; // ������С�Ѷ�
        else
            blockindex = chainActive.Tip(); // ��ȡ������������
    }

    int nShift = (blockindex->nBits >> 24) & 0xff; // ��ȡ nBits �ĸ� 8 λ 2 ����

    double dDiff = // main and testnet (0x1d00ffff) or regtest (0x207fffff) 0x1e0ffff0 (dash)
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff); // �����Ѷ�

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

    return dDiff; // �����Ѷ�
}

UniValue blockheaderToJSON(const CBlockIndex* blockindex)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", blockindex->GetBlockHash().GetHex())); // �����ϣ
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->nHeight + 1; // ����ȷ����
    result.push_back(Pair("confirmations", confirmations)); // ȷ����
    result.push_back(Pair("height", blockindex->nHeight)); // �������߶�
    result.push_back(Pair("version", blockindex->nVersion)); // ����汾��
    result.push_back(Pair("merkleroot", blockindex->hashMerkleRoot.GetHex())); // Ĭ������
    result.push_back(Pair("time", (int64_t)blockindex->nTime)); // ���鴴��ʱ��
    result.push_back(Pair("mediantime", (int64_t)blockindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", (uint64_t)blockindex->nNonce)); // �����
    result.push_back(Pair("bits", strprintf("%08x", blockindex->nBits))); // �Ѷȶ�Ӧֵ
    result.push_back(Pair("difficulty", GetDifficulty(blockindex))); // �Ѷ�
    result.push_back(Pair("chainwork", blockindex->nChainWork.GetHex())); // ������

    if (blockindex->pprev) // ��һ������Ĺ�ϣ
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext) // ��һ������Ĺ�ϣ
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));
    return result;
}

UniValue blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool txDetails = false)
{
    UniValue result(UniValue::VOBJ); // �����������͵ķ��ؽ��
    result.push_back(Pair("hash", block.GetHash().GetHex())); // �ȼ�������Ĺ�ϣ��16 ������ʽ��
    int confirmations = -1; // ��¼�������ȷ����
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex)) // ��������������
        confirmations = chainActive.Height() - blockindex->nHeight + 1; // ����ȷ������ע����������ȷ����Ϊ 1
    result.push_back(Pair("confirmations", confirmations)); // ����ȷ����
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION))); // �����С����λ�ֽڣ�
    result.push_back(Pair("height", blockindex->nHeight)); // ����߶�
    result.push_back(Pair("version", block.nVersion)); // ����汾
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex())); // Ĭ������
    UniValue txs(UniValue::VARR); // �������͵Ľ��׶���
    BOOST_FOREACH(const CTransaction&tx, block.vtx)
    { // ���������б�
        if(txDetails) // false
        { // ����ϸ��
            UniValue objTx(UniValue::VOBJ);
            TxToJSON(tx, uint256(), objTx); // �ѽ�����Ϣת��Ϊ JSON ��ʽ���뵽 objTx
            txs.push_back(objTx);
        }
        else // ���뽻�׹�ϣ
            txs.push_back(tx.GetHash().GetHex());
    }
    result.push_back(Pair("tx", txs)); // ���׼�
    result.push_back(Pair("time", block.GetBlockTime())); // ��ȡ���鴴��ʱ��
    result.push_back(Pair("mediantime", (int64_t)blockindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", (uint64_t)block.nNonce)); // �����
    result.push_back(Pair("bits", strprintf("%08x", block.nBits))); // �Ѷȶ�Ӧֵ
    result.push_back(Pair("difficulty", GetDifficulty(blockindex))); // �Ѷ�
    result.push_back(Pair("chainwork", blockindex->nChainWork.GetHex())); // ��������

    if (blockindex->pprev) // �����ǰһ������
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex())); // ����ǰһ������Ĺ�ϣ
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext) // ������һ������
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex())); // �����һ������Ĺ�ϣ
    return result; // ���ؽ��
}

UniValue getblockcount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // û�в���
        throw runtime_error( // ������Ϣ����
            "getblockcount\n"
            "\nReturns the number of blocks in the longest block chain.\n"
            "\nResult:\n"
            "n    (numeric) The current block count\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockcount", "")
            + HelpExampleRpc("getblockcount", "")
        );

    LOCK(cs_main);
    return chainActive.Height(); // ���ؼ�������߶�
}

UniValue getbestblockhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // 1.������û�в���
        throw runtime_error( // �����������
            "getbestblockhash\n"
            "\nReturns the hash of the best (tip) block in the longest block chain.\n"
            "\nResult\n"
            "\"hex\"      (string) the block hash hex encoded\n"
            "\nExamples\n"
            + HelpExampleCli("getbestblockhash", "")
            + HelpExampleRpc("getbestblockhash", "")
        );

    LOCK(cs_main);
    return chainActive.Tip()->GetBlockHash().GetHex(); // 2.���ؼ������������ϣ�� 16 ����
}

UniValue getdifficulty(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // û�в���
        throw runtime_error( // �����������
            "getdifficulty\n"
            "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nResult:\n"
            "n.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nExamples:\n"
            + HelpExampleCli("getdifficulty", "")
            + HelpExampleRpc("getdifficulty", "")
        );

    LOCK(cs_main); // ����
    return GetDifficulty(); // ���ػ�ȡ���Ѷ�ֵ
}

UniValue mempoolToJSON(bool fVerbose = false)
{
    if (fVerbose)
    { // ���������ϸ��Ϣ
        LOCK(mempool.cs);
        UniValue o(UniValue::VOBJ);
        BOOST_FOREACH(const CTxMemPoolEntry& e, mempool.mapTx)
        { // ������ȡ���׳��еĽ�����Ŀ
            const uint256& hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);
            info.push_back(Pair("size", (int)e.GetTxSize())); // ���״�С
            info.push_back(Pair("fee", ValueFromAmount(e.GetFee()))); // ���׷�
            info.push_back(Pair("modifiedfee", ValueFromAmount(e.GetModifiedFee()))); // �޸ĵĽ��׷�
            info.push_back(Pair("time", e.GetTime())); // ��ǰʱ��
            info.push_back(Pair("height", (int)e.GetHeight())); // ��ǰ����߶�
            info.push_back(Pair("startingpriority", e.GetPriority(e.GetHeight()))); // ��ʼ���ȼ���ͨ�����߶ȣ�
            info.push_back(Pair("currentpriority", e.GetPriority(chainActive.Height()))); // ��ǰ���ȼ�
            info.push_back(Pair("descendantcount", e.GetCountWithDescendants())); // ��������
            info.push_back(Pair("descendantsize", e.GetSizeWithDescendants())); // �����С
            info.push_back(Pair("descendantfees", e.GetModFeesWithDescendants())); // �������
            const CTransaction& tx = e.GetTx();
            set<string> setDepends; // �������������
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                if (mempool.exists(txin.prevout.hash)) // ��ѯ��������������ϣ���ڴ�����Ƿ����
                    setDepends.insert(txin.prevout.hash.ToString()); // ������������
            }

            UniValue depends(UniValue::VARR);
            BOOST_FOREACH(const string& dep, setDepends) // ��������Ŀ�����
            {
                depends.push_back(dep);
            }

            info.push_back(Pair("depends", depends)); // ���뽻������
            o.push_back(Pair(hash.ToString(), info)); // �������� �� ������Ϣ ���
        }
        return o;
    }
    else
    { // ���������������ϣ��
        vector<uint256> vtxid;
        mempool.queryHashes(vtxid); // ��佻�׳��еĽ��׹�ϣ�� vtxid

        UniValue a(UniValue::VARR);
        BOOST_FOREACH(const uint256& hash, vtxid)
            a.push_back(hash.ToString());

        return a;
    }
}

UniValue getrawmempool(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
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

    LOCK(cs_main); // ����

    bool fVerbose = false; // ��ϸ��־��Ĭ��Ϊ false
    if (params.size() > 0)
        fVerbose = params[0].get_bool(); // ��ȡ��ϸ����

    return mempoolToJSON(fVerbose); // ���ڴ�ؽ��״��Ϊ JSON ��ʽ������
}

UniValue getblockhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // ����ֻ�� 1 ��
        throw runtime_error( // �����������
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

    LOCK(cs_main); // ����

    int nHeight = params[0].get_int(); // ��ȡָ��������������Ϊ�������߶�
    if (nHeight < 0 || nHeight > chainActive.Height()) // ���ָ���߶��Ƿ��ڸ��������߶ȷ�Χ��
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    CBlockIndex* pblockindex = chainActive[nHeight]; // ��ȡ��������Ӧ�߶ȵ���������
    return pblockindex->GetBlockHash().GetHex(); // ��ȡ��������Ӧ�����ϣ��ת��Ϊ 16 ���Ʋ�����
}

UniValue getblockheader(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) // ��������Ϊ 1 ���������ϣ�������� 2 ��
        throw runtime_error( // �����������
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

    LOCK(cs_main); // ����

    std::string strHash = params[0].get_str(); // ��ȡ�����ϣ�ַ���
    uint256 hash(uint256S(strHash)); // ���� uint256 �ֲ�����

    bool fVerbose = true; // ��ϸ��Ϣ��־��Ĭ��Ϊ true
    if (params.size() > 1)
        fVerbose = params[1].get_bool(); // ��ȡ�Ƿ���ʾ��ϸ��Ϣ

    if (mapBlockIndex.count(hash) == 0) // �жϹ�ϣ��Ӧ�������Ƿ��������������ӳ��
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlockIndex* pblockindex = mapBlockIndex[hash]; // ��ȡָ����ϣ����������

    if (!fVerbose) // false
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION); // ���л�
        ssBlock << pblockindex->GetBlockHeader(); // ͨ������������ȡ����������ͷ����
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end()); // 16 ���ƻ�
        return strHex; // ����
    }

    return blockheaderToJSON(pblockindex); // ��װ����ͷ��ϢΪ JSON ��ʽ������
}

UniValue getblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) // 1.������ 1 ��������ı����Ĺ�ϣ������� 2 ��
        throw runtime_error( // �����������
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

    std::string strHash = params[0].get_str(); // 2.�Ѳ���ת��Ϊ�ַ���
    uint256 hash(uint256S(strHash)); // ��װ�� uint256 ����

    bool fVerbose = true; // 3.��ϸ��־��Ĭ��Ϊ true
    if (params.size() > 1) // ���е� 2 ������
        fVerbose = params[1].get_bool(); // ��ȡ verbose ��ֵ�������ͣ�

    if (mapBlockIndex.count(hash) == 0) // 4.���ָ����ϣ�Ƿ�����������ӳ����
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block; // ����һ���ֲ����������
    CBlockIndex* pblockindex = mapBlockIndex[hash]; // ��ȡָ����ϣ��Ӧ����������ָ��

    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0) // 5.�����ļ�δ���޼��� �� ����״̬Ϊ�������ļ���Ϊ�������� �� ���������еĽ��׺�Ϊ 0
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Block not available (pruned data)");

    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) // 6.�Ӵ����ϵ��ļ��ж�ȡ������Ϣ
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    if (!fVerbose) // 7.false
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION); // ���л�����
        ssBlock << block; // ������������
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end()); // 16 ���ƻ�
        return strHex; // ����
    }

    return blockToJSON(block, pblockindex); // 8.���������ϢΪ JSON ��ʽ������
}

UniValue gettxoutsetinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // û�в���
        throw runtime_error( // �����������
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

    UniValue ret(UniValue::VOBJ); // �������ͷ��ؽ��

    CCoinsStats stats;
    FlushStateToDisk(); // ˢ��״̬��Ϣ������
    if (pcoinsTip->GetStats(stats)) { // ��ȡ��״̬��Ϣ
        ret.push_back(Pair("height", (int64_t)stats.nHeight)); // �������߶�
        ret.push_back(Pair("bestblock", stats.hashBlock.GetHex())); // ��������ϣ
        ret.push_back(Pair("transactions", (int64_t)stats.nTransactions)); // ������
        ret.push_back(Pair("txouts", (int64_t)stats.nTransactionOutputs)); // ���������
        ret.push_back(Pair("bytes_serialized", (int64_t)stats.nSerializedSize)); // ���л����ֽڴ�С
        ret.push_back(Pair("hash_serialized", stats.hashSerialized.GetHex())); // ���л��Ĺ�ϣ
        ret.push_back(Pair("total_amount", ValueFromAmount(stats.nTotalAmount))); // �ܽ��
    }
    return ret; // ���ؽ��
}

UniValue gettxout(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3) // ����Ϊ 2 ���� 3 ��
        throw runtime_error( // �����������
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

    UniValue ret(UniValue::VOBJ); // Ŀ�����͵Ľ������

    std::string strHash = params[0].get_str(); // ��ȡ��������
    uint256 hash(uint256S(strHash));
    int n = params[1].get_int(); // ��ȡ�����������
    bool fMempool = true; // �Ƿ�����ڴ���ڽ��׵ı�־��Ĭ��Ϊ true
    if (params.size() > 2)
        fMempool = params[2].get_bool(); // ��ȡָ�����ڴ�ر�־

    CCoins coins; // ����һ�����޼��Ľ��װ汾����ֻ����Ԫ���ݺ�δ���ѵĽ��������
    if (fMempool) { // �������ڴ���еĽ���
        LOCK(mempool.cs); // �ڴ������
        CCoinsViewMemPool view(pcoinsTip, mempool); // �����ڴ�����ò鿴����
        if (!view.GetCoins(hash, coins)) // ��ȡ�޼��潻��
            return NullUniValue;
        mempool.pruneSpent(hash, coins); // TODO: this should be done by the CCoinsViewMemPool
    } else { // ���������ڴ�صĽ���
        if (!pcoinsTip->GetCoins(hash, coins)) // ֱ�ӻ�ȡ��������ı�����
            return NullUniValue;
    }
    if (n<0 || (unsigned int)n>=coins.vout.size() || coins.vout[n].IsNull()) // ���������Χ��⣬���������Ӧ���Ϊ��
        return NullUniValue;

    BlockMap::iterator it = mapBlockIndex.find(pcoinsTip->GetBestBlock()); // ��ȡ�����������ӳ�������
    CBlockIndex *pindex = it->second; // ��ȡ�����������
    ret.push_back(Pair("bestblock", pindex->GetBlockHash().GetHex())); // ��������ϣ
    if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT) // ���ҵĸ߶�Ϊ 0x7FFFFFFF
        ret.push_back(Pair("confirmations", 0)); // δ������0 ȷ����
    else // �����ʾ������
        ret.push_back(Pair("confirmations", pindex->nHeight - coins.nHeight + 1)); // ��ȡȷ����
    ret.push_back(Pair("value", ValueFromAmount(coins.vout[n].nValue))); // ������
    UniValue o(UniValue::VOBJ);
    ScriptPubKeyToJSON(coins.vout[n].scriptPubKey, o, true); // ��Կ�ű�ת��Ϊ JSON ��ʽ
    ret.push_back(Pair("scriptPubKey", o)); // ��Կ�ű�
    ret.push_back(Pair("version", coins.nVersion)); // �汾��
    ret.push_back(Pair("coinbase", coins.fCoinBase)); // �Ƿ�Ϊ���ҽ���

    return ret;
}

UniValue verifychain(const UniValue& params, bool fHelp)
{
    int nCheckLevel = GetArg("-checklevel", DEFAULT_CHECKLEVEL); // ���ȼ���Ĭ�� 3
    int nCheckDepth = GetArg("-checkblocks", DEFAULT_CHECKBLOCKS); // ��������Ĭ�� 288
    if (fHelp || params.size() > 2) // ������� 2 ��
        throw runtime_error( // �����������
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

    LOCK(cs_main); // ����

    if (params.size() > 0)
        nCheckLevel = params[0].get_int(); // ��ȡָ���ļ��ȼ�
    if (params.size() > 1)
        nCheckDepth = params[1].get_int(); // ��ȡָ���ü�������Ϊ������

    return CVerifyDB().VerifyDB(Params(), pcoinsTip, nCheckLevel, nCheckDepth); // ������������ݿ�
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
    if (fHelp || params.size() != 0) // ������û�в���
        throw runtime_error( // ������Ϣ����
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

    UniValue obj(UniValue::VOBJ); // ����һ��Ŀ�����
    obj.push_back(Pair("chain",                 Params().NetworkIDString())); // ���� ID������ �� ������
    obj.push_back(Pair("blocks",                (int)chainActive.Height())); // ��ǰ����߶�
    obj.push_back(Pair("headers",               pindexBestHeader ? pindexBestHeader->nHeight : -1)); // ��ǰ�������ͷ�߶ȣ�ͬ����߶�
    obj.push_back(Pair("bestblockhash",         chainActive.Tip()->GetBlockHash().GetHex())); // ��������ϣ��16 ���ƣ�
    obj.push_back(Pair("difficulty",            (double)GetDifficulty())); // �ڿ��Ѷ�
    obj.push_back(Pair("mediantime",            (int64_t)chainActive.Tip()->GetMedianTimePast())); // ��ǰʱ��
    obj.push_back(Pair("verificationprogress",  Checkpoints::GuessVerificationProgress(Params().Checkpoints(), chainActive.Tip()))); // ��֤���ȣ������������й�
    obj.push_back(Pair("chainwork",             chainActive.Tip()->nChainWork.GetHex())); // ��ǰ������������16 ���ƣ�
    obj.push_back(Pair("pruned",                fPruneMode)); // �Ƿ����޼�ģʽ

    const Consensus::Params& consensusParams = Params().GetConsensus();
    CBlockIndex* tip = chainActive.Tip();
    UniValue softforks(UniValue::VARR);
    UniValue bip9_softforks(UniValue::VARR);
    softforks.push_back(SoftForkDesc("bip34", 2, tip, consensusParams));
    softforks.push_back(SoftForkDesc("bip66", 3, tip, consensusParams));
    softforks.push_back(SoftForkDesc("bip65", 4, tip, consensusParams));
    bip9_softforks.push_back(BIP9SoftForkDesc("csv", consensusParams, Consensus::DEPLOYMENT_CSV));
    obj.push_back(Pair("softforks",             softforks)); // ��ֲ�
    obj.push_back(Pair("bip9_softforks", bip9_softforks)); // bip9_��ֲ�

    if (fPruneMode) // ���������޼�ģʽ
    {
        CBlockIndex *block = chainActive.Tip();
        while (block && block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA))
            block = block->pprev;

        obj.push_back(Pair("pruneheight",        block->nHeight)); // �����޼����ĸ߶�
    }
    return obj; // ����Ŀ�����
}

/** Comparison function for sorting the getchaintips heads.  */ // ���� getchaintips ������������ͷ�ıȽ���
struct CompareBlocksByHeight // ��������ͨ���߶ȱȽ�����
{
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare // ȷ����ͬ�߶Ȳ�ͬ�Ŀ�ȽϺ󲻵�
           equal. Use the pointers themselves to make a distinction. */ // ʹ��ָ�����֡�

        if (a->nHeight != b->nHeight)
          return (a->nHeight > b->nHeight);

        return a < b;
    }
};

UniValue getchaintips(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // û�в���
        throw runtime_error( // �����������
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

    LOCK(cs_main); // ����

    /* Build up a list of chain tips.  We start with the list of all // ���������б�
       known blocks, and successively remove blocks that appear as pprev
       of another block.  */ // ���Ǵ���֪����б�ʼ���������Ƴ���һ������� pprev ���飬�Ի�ȡ��������������
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips; // ����������������
    BOOST_FOREACH(const PAIRTYPE(const uint256, CBlockIndex*)& item, mapBlockIndex) // ������������ӳ��
        setTips.insert(item.second); // ����������������
    BOOST_FOREACH(const PAIRTYPE(const uint256, CBlockIndex*)& item, mapBlockIndex) // ������������ӳ��
    {
        const CBlockIndex* pprev = item.second->pprev;
        if (pprev)
            setTips.erase(pprev); // �Ƴ������ǰһ������
    }

    // Always report the currently active tip. // ���Ǳ��浱ǰ���������
    setTips.insert(chainActive.Tip()); // ���뵱ǰ����������������

    /* Construct the output array.  */ // �����������
    UniValue res(UniValue::VARR); // �����������͵Ľ������
    BOOST_FOREACH(const CBlockIndex* block, setTips) // ��������������������
    {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("height", block->nHeight)); // ���߶ȣ�����������
        obj.push_back(Pair("hash", block->phashBlock->GetHex())); // �����ϣ

        const int branchLen = block->nHeight - chainActive.FindFork(block)->nHeight; // �����֧����
        obj.push_back(Pair("branchlen", branchLen));

        string status; // ��״̬
        if (chainActive.Contains(block)) { // ��鵱ǰ���������Ƿ���ڸ�����
            // This block is part of the currently active chain. // �������ǵ�ǰ��������һ����
            status = "active"; // ״̬���Ϊ����
        } else if (block->nStatus & BLOCK_FAILED_MASK) { // �ÿ��������֮һ��������Ч
            // This block or one of its ancestors is invalid.
            status = "invalid"; // ״̬���Ϊ��Ч
        } else if (block->nChainTx == 0) { // �ÿ��޷����ӣ���Ϊ�ÿ���丸��֮һ�������������ݶ�ʧ
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only"; // ״̬���Ϊ������ͷ
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) { // ����������ȫ��֤���������Ǽ�������һ����
            // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized. // �������Ǽ�������飬��������
            status = "valid-fork"; // ״̬���Ϊ��֤�ֲ�
        } else if (block->IsValid(BLOCK_VALID_TREE)) { // ������ͷ��Ч������û�б���֤��
            // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain. // ���ܴ���������Ч����һ���֡�
            status = "valid-headers"; // ״̬���Ϊ��֤ͷ��
        } else {
            // No clue.
            status = "unknown";
        }
        obj.push_back(Pair("status", status));

        res.push_back(obj);
    }

    return res; // ���ؽ������
}

UniValue mempoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ); // ����һ��Ŀ�����
    ret.push_back(Pair("size", (int64_t) mempool.size())); // �ڴ�ص�ǰ��С
    ret.push_back(Pair("bytes", (int64_t) mempool.GetTotalTxSize())); // �ڴ�ؽ����ܴ�С
    ret.push_back(Pair("usage", (int64_t) mempool.DynamicMemoryUsage())); // ��̬�ڴ�����
    size_t maxmempool = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    ret.push_back(Pair("maxmempool", (int64_t) maxmempool)); // �ڴ�صĴ�С
    ret.push_back(Pair("mempoolminfee", ValueFromAmount(mempool.GetMinFee(maxmempool).GetFeePerK()))); // �ڴ����С����

    return ret;
}

UniValue getmempoolinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // û�в���
        throw runtime_error( // �����������
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

    return mempoolInfoToJSON(); // �ѽ����ڴ����Ϣ���Ϊ JSON ��ʽ������
}

UniValue invalidateblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
            "invalidateblock \"hash\"\n"
            "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to mark as invalid\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("invalidateblock", "\"blockhash\"")
            + HelpExampleRpc("invalidateblock", "\"blockhash\"")
        );

    std::string strHash = params[0].get_str(); // ��ȡָ���������ϣ
    uint256 hash(uint256S(strHash)); // ת��Ϊ uint256 ����
    CValidationState state;

    {
        LOCK(cs_main); // ����
        if (mapBlockIndex.count(hash) == 0) // ��ָ����ϣ����������ӳ���б��в�����
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash]; // ��ȡָ����ϣ��Ӧ����������
        InvalidateBlock(state, Params().GetConsensus(), pblockindex); // ʹ��������Ч��
    }

    if (state.IsValid()) { // ����֤״̬��Ч
        ActivateBestChain(state, Params()); // ���������
    }

    if (!state.IsValid()) { // �ٴ���֤����״̬
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue; // ���ؿ�ֵ
}

UniValue reconsiderblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
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

    std::string strHash = params[0].get_str(); // ��ȡָ�������ϣ
    uint256 hash(uint256S(strHash)); // ���� uint256 ����
    CValidationState state;

    {
        LOCK(cs_main); // ����
        if (mapBlockIndex.count(hash) == 0) // ����������ӳ���б���û��ָ������
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash]; // ��ȡָ����������
        ReconsiderBlock(state, pblockindex); // �ٿ�������
    }

    if (state.IsValid()) { // ����֤״̬��Ч
        ActivateBestChain(state, Params()); // ���������
    }

    if (!state.IsValid()) { // ��鼤����֤״̬
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue; // ���ؿ�ֵ
}
