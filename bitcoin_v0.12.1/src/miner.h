// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include "primitives/block.h"

#include <stdint.h>

/** Search the genesis block */
void getGenesisBlock(CBlock *pblock);

class CBlockIndex; // 所需类的前置声明
class CChainParams;
class CReserveKey;
class CScript;
class CWallet;
namespace Consensus { struct Params; };

static const bool DEFAULT_GENERATE = false; // 挖矿状态，默认关闭
static const int DEFAULT_GENERATE_THREADS = 1; // 挖矿线程数，默认为 1

static const bool DEFAULT_PRINTPRIORITY = false;

struct CBlockTemplate // 区块模板类
{
    CBlock block; // 区块对象
    std::vector<CAmount> vTxFees; // 交易手续费
    std::vector<int64_t> vTxSigOps; // 交易签名操作
};

/** Run the miner threads */ // 运行矿工线程
void GenerateBitcoins(bool fGenerate, int nThreads, const CChainParams& chainparams); // 杀掉矿工线程或创建新的矿工线程
/** Generate a new block, without valid proof-of-work */
CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const CScript& scriptPubKeyIn); // 生成一个新块，不带工作量证明
/** Modify the extranonce in a block */ // 修改区块内的 extranonce
void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev);

#endif // BITCOIN_MINER_H
