// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "main.h"
#include "net.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#include <queue>

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

class ScoreCompare
{
public:
    ScoreCompare() {}

    bool operator()(const CTxMemPool::txiter a, const CTxMemPool::txiter b)
    {
        return CompareTxMemPoolEntryByScore()(*b,*a); // Convert to less than
    }
};

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime; // ��¼���鴴����ʱ��
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime()); // pending

    if (nOldTime < nNewTime) // ��ʱ����ھ�ʱ��
        pblock->nTime = nNewTime; // ��������Ĵ���ʱ��

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) // �ڲ������У���������ʱ���ı������Ѷ�
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams); // pending

    return nNewTime - nOldTime; // �����¾�ʱ���
}

CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const CScript& scriptPubKeyIn)
{
    // Create new block
    auto_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate()); // ����һ���µ�����ģ�壨�������������Ѻͽ���ǩ��������
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // Create coinbase tx
    CMutableTransaction txNew; // �������ҽ��׶���
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull(); // ����Ϊ��
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = scriptPubKeyIn; // �����Կ�ű�

    // Add dummy coinbase tx as first transaction
    pblock->vtx.push_back(CTransaction()); // ��ӼٵĴ��ҽ�����Ϊ��һ�ʽ��׵������б���
    pblocktemplate->vTxFees.push_back(-1); // updated at end // �޽���������
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end // �޽���ǩ������

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE); // ��ϣ����������������С��Ĭ�� 750,000������ 1M��
    // Limit to between 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize)); // ��ȡ���������С���������

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE); // Ĭ���������ȼ���С��Ĭ��Ϊ 0
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize); // ���ڰ��������ȼ��Ľ���

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE); // Ĭ�������С��С���ƣ�Ĭ��Ϊ 0
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    CTxMemPool::setEntries inBlock;
    CTxMemPool::setEntries waitSet;

    // This vector will be sorted into a priority queue:
    vector<TxCoinAgePriority> vecPriority;
    TxCoinAgePriorityCompare pricomparer;
    std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash> waitPriMap;
    typedef std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash>::iterator waitPriIter;
    double actualPriority = -1;

    std::priority_queue<CTxMemPool::txiter, std::vector<CTxMemPool::txiter>, ScoreCompare> clearedTxs;
    bool fPrintPriority = GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY); // ��ӡ���ȼ���־��Ĭ�Ϲر�
    uint64_t nBlockSize = 1000; // �����С
    uint64_t nBlockTx = 0; // �����ڽ�����
    unsigned int nBlockSigOps = 100;
    int lastFewTxs = 0;
    CAmount nFees = 0;

    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = chainActive.Tip();
        const int nHeight = pindexPrev->nHeight + 1;
        pblock->nTime = GetAdjustedTime();
        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

        pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus()); // ��������汾
        // -regtest only: allow overriding block.nVersion with
        // -blockversion=N to test forking scenarios
        if (chainparams.MineBlocksOnDemand())
            pblock->nVersion = GetArg("-blockversion", pblock->nVersion);

        int64_t nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                                ? nMedianTimePast
                                : pblock->GetBlockTime();

        bool fPriorityBlock = nBlockPrioritySize > 0;
        if (fPriorityBlock) {
            vecPriority.reserve(mempool.mapTx.size());
            for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
                 mi != mempool.mapTx.end(); ++mi)
            {
                double dPriority = mi->GetPriority(nHeight);
                CAmount dummy;
                mempool.ApplyDeltas(mi->GetTx().GetHash(), dPriority, dummy);
                vecPriority.push_back(TxCoinAgePriority(dPriority, mi));
            }
            std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
        }

        CTxMemPool::indexed_transaction_set::nth_index<3>::type::iterator mi = mempool.mapTx.get<3>().begin();
        CTxMemPool::txiter iter;

        while (mi != mempool.mapTx.get<3>().end() || !clearedTxs.empty())
        {
            bool priorityTx = false;
            if (fPriorityBlock && !vecPriority.empty()) { // add a tx from priority queue to fill the blockprioritysize
                priorityTx = true;
                iter = vecPriority.front().second;
                actualPriority = vecPriority.front().first;
                std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                vecPriority.pop_back();
            }
            else if (clearedTxs.empty()) { // add tx with next highest score
                iter = mempool.mapTx.project<0>(mi);
                mi++;
            }
            else {  // try to add a previously postponed child tx
                iter = clearedTxs.top();
                clearedTxs.pop();
            }

            if (inBlock.count(iter))
                continue; // could have been added to the priorityBlock

            const CTransaction& tx = iter->GetTx();

            bool fOrphan = false;
            BOOST_FOREACH(CTxMemPool::txiter parent, mempool.GetMemPoolParents(iter))
            {
                if (!inBlock.count(parent)) {
                    fOrphan = true;
                    break;
                }
            }
            if (fOrphan) {
                if (priorityTx)
                    waitPriMap.insert(std::make_pair(iter,actualPriority));
                else
                    waitSet.insert(iter);
                continue;
            }

            unsigned int nTxSize = iter->GetTxSize();
            if (fPriorityBlock &&
                (nBlockSize + nTxSize >= nBlockPrioritySize || !AllowFree(actualPriority))) {
                fPriorityBlock = false;
                waitPriMap.clear();
            }
            if (!priorityTx &&
                (iter->GetModifiedFee() < ::minRelayTxFee.GetFee(nTxSize) && nBlockSize >= nBlockMinSize)) {
                break;
            }
            if (nBlockSize + nTxSize >= nBlockMaxSize) {
                if (nBlockSize >  nBlockMaxSize - 100 || lastFewTxs > 50) {
                    break;
                }
                // Once we're within 1000 bytes of a full block, only look at 50 more txs
                // to try to fill the remaining space.
                if (nBlockSize > nBlockMaxSize - 1000) {
                    lastFewTxs++;
                }
                continue;
            }

            if (!IsFinalTx(tx, nHeight, nLockTimeCutoff))
                continue;

            unsigned int nTxSigOps = iter->GetSigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS) {
                if (nBlockSigOps > MAX_BLOCK_SIGOPS - 2) {
                    break;
                }
                continue;
            }

            CAmount nTxFees = iter->GetFee();
            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx; // �����ڽ������� 1
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees; // �ۼӽ��׷�

            if (fPrintPriority) // ��ӡ���ȼ�
            {
                double dPriority = iter->GetPriority(nHeight);
                CAmount dummy;
                mempool.ApplyDeltas(tx.GetHash(), dPriority, dummy);
                LogPrintf("priority %.1f fee %s txid %s\n",
                          dPriority , CFeeRate(iter->GetModifiedFee(), nTxSize).ToString(), tx.GetHash().ToString());
            }

            inBlock.insert(iter);

            // Add transactions that depend on this one to the priority queue
            BOOST_FOREACH(CTxMemPool::txiter child, mempool.GetMemPoolChildren(iter))
            {
                if (fPriorityBlock) {
                    waitPriIter wpiter = waitPriMap.find(child);
                    if (wpiter != waitPriMap.end()) {
                        vecPriority.push_back(TxCoinAgePriority(wpiter->second,child));
                        std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                        waitPriMap.erase(wpiter);
                    }
                }
                else {
                    if (waitSet.count(child)) {
                        clearedTxs.push(child);
                        waitSet.erase(child);
                    }
                }
            }
        }
        nLastBlockTx = nBlockTx; // ���������ڽ�����
        nLastBlockSize = nBlockSize; // ���������С
        LogPrintf("CreateNewBlock(): total size %u txs: %u fees: %ld sigops %d\n", nBlockSize, nBlockTx, nFees, nBlockSigOps);

        // Compute final coinbase transaction. // �����㴴�ҽ������
        txNew.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus()); // ���㴴�ҽ������ֵ�����齱������ͨ����ǰ����߶Ⱥ͹�ʶ
        txNew.vin[0].scriptSig = CScript() << nHeight << OP_0; // ����ý��������ǩ���ű���������ĸ߶ȣ�OP_0 ��ʾһ���ֽڿմ�������ջ
        pblock->vtx[0] = txNew; // ���봴�ҽ���
        pblocktemplate->vTxFees[0] = -nFees; // ���㽻�������ѣ�Ϊ 0

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash(); // ��ȡ�������ϣ
        UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev); 
        pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus()); // ��ȡ�Ѷȶ�Ӧֵ
        pblock->nNonce         = 0; // ������� 0������ 0 ��ʼ�ҿ�
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]); // ��ȡ���ҽ���ǩ��������

        CValidationState state;
        if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) { // ��֤�����Ƿ���Ч
            throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
        }
    }

    return pblocktemplate.release(); // �ͷŲ���������ģ��ָ��
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock; // ��ֻ֤��ʼ��һ��
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce; // ������� 1
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(pblock->vtx[0]); // ����һ�ʿɱ�Ĵ��ҽ���
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS; // ������������ǩ���ű�
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = txCoinbase; // �Ѵ��ҽ��׼��뽻���б�
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock); // ���㽻���б��Ĭ����������ϣ�������ҽ��׵� id
}

//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
// �ڲ���

//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// The nonce is usually preserved between calls, but periodically or if the
// nonce is 0xffff0000 or above, the block is rebuilt and nNonce starts over at
// zero.
// ScanHash ɨ���������Ѱ��һ��������һЩ 0 λ��ɢ�С������ͨ���ڵ��ü䱣���������������ڻ򳬹� 0xffff0000���ؽ����鲢���������Ϊ 0��
bool static ScanHash(const CBlockHeader *pblock, uint32_t& nNonce, uint256 *phash) // �ڿ��㷨
{
    // Write the first 76 bytes of the block header to a double-SHA256 state.
    CHash256 hasher; // ������ͷǰ 76 �ֽڣ��������������һ�� DSHA256 ״̬��
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *pblock; // ��������ͷ���ݣ�80 �ֽڣ�
    assert(ss.size() == 80); // BlockHeader Size: 80 Bytes
    hasher.Write((unsigned char*)&ss[0], 76); // д��ǰ 5 ���ֶΣ�nVersion��hashPrevBlock��hashMerkleRoot��nTime��nBits�������һ���ֶ� nNonce ��Ϊ����

    while (true) {
        nNonce++; // �����������ÿ�μ� 1

        // Write the last 4 bytes of the block header (the nonce) to a copy of
        // the double-SHA256 state, and compute the result. // д������������� DSHA256
        CHash256(hasher).Write((unsigned char*)&nNonce, 4).Finalize((unsigned char*)phash);

        // Return the nonce if the hash has at least some zero bits,
        // caller will check if it has enough to reach the target
        if (((uint16_t*)phash)[15] == 0) // �� 32 �ֽڣ����һ��Ԫ�أ�2 ���ֽڣ�Ϊ 0������� 16 λΪ 0���򷵻�
            return true; // ��������� 4 �� 16 ���Ƶ� 0 �ŷ��ظ�����������ٺ��Ѷ�Ŀ��ֵ�ıȽϴ���

        // If nothing found after trying for a while, return -1
        if ((nNonce & 0xfff) == 0)
            return false;
    }
}

static bool ProcessBlockFound(const CBlock* pblock, const CChainParams& chainparams)
{
    LogPrintf("%s\n", pblock->ToString()); // ��¼�����ϣ������ͷ 6 ���������ÿ�ʽ�����ϸ��Ϣ����־
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue)); // ��¼���ҽ��ײ����ҵ�����

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash()) // ��֤������ĸ������Ƿ�Ϊ��������
            return error("BitcoinMiner: generated block is stale");
    }

    // Inform about the new block
    GetMainSignals().BlockFound(pblock->GetHash()); // ֪ͨ������Ĺ�ϣ���� validationinterface.cpp �ж��壬���ø�������������Ϊ 0

    // Process this block the same as if we had received it from another node
    CValidationState state; // Ĭ��Ϊ��Ч״̬
    if (!ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL)) // ���������飨�洢�����鵽���ء������������
        return error("BitcoinMiner: ProcessNewBlock, block not accepted");

    return true;
}

void getGenesisBlock(CBlock *pblock) // ��ȡ��������Ļ�����Ϣ��nNonce, hash, merkleroot��
{
    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);
    printf("hashTarget: %s\n", hashTarget.ToString().c_str());
    uint256 hash; // ����ȡ�� hash
    uint32_t nNonce = 0; // �������ʼ��Ϊ 0
    int64_t nStart = GetTime(); // ��ȡ��ǰʱ��
    while (true)
    {
        if (ScanHash(pblock, nNonce, &hash)) // ɨ������������ hash
        {
            printf("block hash: %s", hash.ToString().c_str());
            if (UintToArith256(hash) <= hashTarget) // ��С���Ѷ�Ŀ��ֵ������������
            {
                printf(" true\n" // ���������ҵ�
                       "Congratulation! You found the genesis block. total time: %lds\n"
                       "the nNonce: %u\n"
                       "genesis block hash: %s\n"
                       "genesis block merkle root: %s\n", GetTime() - nStart, nNonce, hash.ToString().c_str(), pblock->hashMerkleRoot.ToString().c_str());
                break;
            }
            else
            {
           	    printf(" false\n");
            }
        }
    }
}

void static BitcoinMiner(const CChainParams& chainparams)
{
    LogPrintf("BitcoinMiner started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST); // �����߳����ȼ����궨���� compat.h ��
    RenameThread("bitcoin-miner"); // �������߳�Ϊ���رҿ�

    unsigned int nExtraNonce = 0; // Nonce: Number used once/Number once ��ʾ�������ֻ��һ��

    boost::shared_ptr<CReserveScript> coinbaseScript;
    GetMainSignals().ScriptForMining(coinbaseScript); // ���ҽ��׽ű�

    try {
        // Throw an error if no script was provided.  This can happen
        // due to some internal error but also if the keypool is empty.
        // In the latter case, already the pointer is NULL.
        if (!coinbaseScript || coinbaseScript->reserveScript.empty()) // ��Ҫ���ҽű������ڿ������һ��Ǯ��
            throw std::runtime_error("No coinbase script available (mining requires a wallet)");

        while (true) { // ѭ���ڿ�
            if (chainparams.MiningRequiresPeers()) { // �����������������ͻع���������������Ե����ڿ�
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.
                do {
                    bool fvNodesEmpty; // �ڵ��б�Ϊ�յı�־
                    {
                        LOCK(cs_vNodes);
                        fvNodesEmpty = vNodes.empty(); // �������ӵĽڵ��б��Ƿ�Ϊ��
                    }
#if 1 // for debug
                    LogPrintf("fvNodesEmpty: %d\n", fvNodesEmpty);
                    LogPrintf("IsInitialBlockDownload(): %d\n", IsInitialBlockDownload());
#endif
                    if (!fvNodesEmpty && !IsInitialBlockDownload()) // ���뽨��һ�����ӣ������ܵ����ڿ� �� ��ɳ�ʼ��������
                        break; // �����͹���������������������ܿ�ʼ�ڿ�
                    MilliSleep(1000); // ˯ 1s
                } while (true);
            }

            //
            // Create new block
            //
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated(); // ��ȡ�ڴ���н��׸��µ�����
            CBlockIndex* pindexPrev = chainActive.Tip(); // ��ȡ�������飨�����һ�飩��Ϊ�½�����ĸ�����

            auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(chainparams, coinbaseScript->reserveScript)); // �����µ�����ģ�壨����ͷ��Ĭ����������ϣ�ֶ�Ϊ�գ�
            if (!pblocktemplate.get())
            {
                LogPrintf("Error in BitcoinMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
                return;
            }
            CBlock *pblock = &pblocktemplate->block; // ��ȡ�������
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce); // �ı䴴�ҽ��׵�����ű��������㴴�������Ĭ����������ϣ

            LogPrintf("Running BitcoinMiner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
                ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

            //
            // Search // �ڿ����
            //
            int64_t nStart = GetTime(); // ��¼��ʼ�ڿ��ʱ��
            arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits); // �����ڵ�ǰ����Ѷ�Ŀ��ֵ
            uint256 hash; // ���浱ǰ��Ĺ�ϣ
            uint32_t nNonce = 0; // �������ʼ���� 0
            while (true) { // ��һ����
                // Check if something found
                if (ScanHash(pblock, nNonce, &hash)) // �ڿ�hash ��� 16 λΪ 0 ����������
                {
#if 1 // for debug
					LogPrintf("Search now\n");
#endif
                    if (UintToArith256(hash) <= hashTarget) // ת��ΪС��ģʽ�����Ѷ�Ŀ��ֵ�Ƚϣ��ж��Ƿ�Ϊ�ϸ�Ŀ�
                    { // ����������С��Ŀ��ֵ��
                        // Found a solution
                        pblock->nNonce = nNonce; // ��¼��ǰ�����������ͷ
                        assert(hash == pblock->GetHash()); // ��֤һ������Ĺ�ϣ

                        SetThreadPriority(THREAD_PRIORITY_NORMAL); // ����ڿ��߳����ȼ�
                        LogPrintf("BitcoinMiner:\n");
                        LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex(), hashTarget.GetHex()); // ��¼�ڵ�����������Ϣ
                        ProcessBlockFound(pblock, chainparams); // ��һ�����������֪ͨ�����顢���ش洢�����鲢�����������
                        SetThreadPriority(THREAD_PRIORITY_LOWEST); // �����ڿ��߳����ȼ�
                        coinbaseScript->KeepScript(); // ת�� KeepKey() ����Կ�����Ƴ�����Կ

                        // In regression test mode, stop mining after a block is found.
                        if (chainparams.MineBlocksOnDemand()) // �ع���������ڵ�һ������̱߳��ж�
                            throw boost::thread_interrupted();

                        break; // ��������������һ����
                    }
                } // �ڵ��Ŀ鲻��������

                // Check for stop or if block needs to be rebuilt
                boost::this_thread::interruption_point(); // �����жϵ�
                // Regtest mode doesn't require peers
                if (vNodes.empty() && chainparams.MiningRequiresPeers()) // ���ڷǻع������������ʱ
                    break; // �����ڿ�˯��
                if (nNonce >= 0xffff0000) // �ڿ�������� 0xffff0000 �Σ����ڿ�ʧ��
                    break; // ���������½��飨�������飩�ڿ�
                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60) // ��ǰ�ڴ�ؽ��׸��µ������������½�����ǰ�ڴ�ؽ��׸��µ����� �� ��һ�����ʱ�䳬�� 60s
                    break; // �����������������ڿ�
                if (pindexPrev != chainActive.Tip()) // ��ǰ��������ı䣬�������ڵ��鲢�㲥��֤����������
                    break; // �����������������ڿ�

                // Update nTime every few seconds
                if (UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev) < 0) // ��������ʱ�䣬�����ظ��µ�ʱ���������л���� nBits��
                    break; // Recreate the block if the clock has run backwards, // ���ʱ�Ӳ�׼����󣩣����������ؽ�����
                           // so that we can use the correct time.
                if (chainparams.GetConsensus().fPowAllowMinDifficultyBlocks) // �ڲ������л������Ѷ�Ŀ��ֵ
                {
                    // Changing pblock->nTime can change work required on testnet: // �ڲ������иı�����ʱ����Ըı�����Ĺ�����
                    hashTarget.SetCompact(pblock->nBits);
                }
            }
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("BitcoinMiner terminated\n");
        throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("BitcoinMiner runtime error: %s\n", e.what());
        return;
    }
}

void GenerateBitcoins(bool fGenerate, int nThreads, const CChainParams& chainparams)
{
    static boost::thread_group* minerThreads = NULL; // ���߳���ָ�����

    if (nThreads < 0) // �������߳���С�� 0
        nThreads = GetNumCores(); // ��ȡ CPU ������Ϊ�ڿ��߳���

    if (minerThreads != NULL) // ��֤�߳���ָ��Ϊ�գ�����ǰ�Ѿ����ڿ��̣߳���ֹͣ��ǰ�߳�
    {
        minerThreads->interrupt_all(); // �ж��߳����е������߳�
        delete minerThreads; // ɾ�����ÿ�
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate) // ��֤�������߳������ڿ��־��
        return;

    minerThreads = new boost::thread_group(); // �����յĿ��߳���
    for (int i = 0; i < nThreads; i++) // ����ָ���߳��� nThreads �����رҿ��߳� BitcoinMiner
        minerThreads->create_thread(boost::bind(&BitcoinMiner, boost::cref(chainparams)));
}
