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

class CBlockIndex; // �������ǰ������
class CChainParams;
class CReserveKey;
class CScript;
class CWallet;
namespace Consensus { struct Params; };

static const bool DEFAULT_GENERATE = false; // �ڿ�״̬��Ĭ�Ϲر�
static const int DEFAULT_GENERATE_THREADS = 1; // �ڿ��߳�����Ĭ��Ϊ 1

static const bool DEFAULT_PRINTPRIORITY = false;

struct CBlockTemplate // ����ģ����
{
    CBlock block; // �������
    std::vector<CAmount> vTxFees; // ����������
    std::vector<int64_t> vTxSigOps; // ����ǩ������
};

/** Run the miner threads */ // ���п��߳�
void GenerateBitcoins(bool fGenerate, int nThreads, const CChainParams& chainparams); // ɱ�����̻߳򴴽��µĿ��߳�
/** Generate a new block, without valid proof-of-work */
CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const CScript& scriptPubKeyIn); // ����һ���¿飬����������֤��
/** Modify the extranonce in a block */ // �޸������ڵ� extranonce
void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev);

#endif // BITCOIN_MINER_H
