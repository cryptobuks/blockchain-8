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
    int64_t nOldTime = pblock->nTime; // 记录区块创建的时间
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime()); // pending

    if (nOldTime < nNewTime) // 新时间大于旧时间
        pblock->nTime = nNewTime; // 更新区块的创建时间

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) // 在测试网中，更新区块时间会改变区块难度
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams); // pending

    return nNewTime - nOldTime; // 返回新旧时间差
}

CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const CScript& scriptPubKeyIn)
{
    // Create new block
    auto_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate()); // 创建一个新的区块模板（包含交易手续费和交易签名操作）
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // Create coinbase tx
    CMutableTransaction txNew; // 创建创币交易对象
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull(); // 输入为空
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = scriptPubKeyIn; // 输出公钥脚本

    // Add dummy coinbase tx as first transaction
    pblock->vtx.push_back(CTransaction()); // 添加假的创币交易作为第一笔交易到交易列表中
    pblocktemplate->vTxFees.push_back(-1); // updated at end // 无交易手续费
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end // 无交易签名操作

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE); // 你希望创建的最大区块大小，默认 750,000（不到 1M）
    // Limit to between 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize)); // 获取真正区块大小的最大限制

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE); // 默认区块优先级大小，默认为 0
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize); // 用于包含高优先级的交易

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE); // 默认区块大小最小限制，默认为 0
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
    bool fPrintPriority = GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY); // 打印优先级标志，默认关闭
    uint64_t nBlockSize = 1000; // 区块大小
    uint64_t nBlockTx = 0; // 区块内交易数
    unsigned int nBlockSigOps = 100;
    int lastFewTxs = 0;
    CAmount nFees = 0;

    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = chainActive.Tip();
        const int nHeight = pindexPrev->nHeight + 1;
        pblock->nTime = GetAdjustedTime();
        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

        pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus()); // 计算区块版本
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
            ++nBlockTx; // 区块内交易数加 1
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees; // 累加交易费

            if (fPrintPriority) // 打印优先级
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
        nLastBlockTx = nBlockTx; // 最新区块内交易数
        nLastBlockSize = nBlockSize; // 最新区块大小
        LogPrintf("CreateNewBlock(): total size %u txs: %u fees: %ld sigops %d\n", nBlockSize, nBlockTx, nFees, nBlockSigOps);

        // Compute final coinbase transaction. // 最后计算创币交易输出
        txNew.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus()); // 计算创币交易输出值（区块奖励），通过当前区块高度和共识
        txNew.vin[0].scriptSig = CScript() << nHeight << OP_0; // 导入该交易输入的签名脚本，新区块的高度，OP_0 表示一个字节空串被推入栈
        pblock->vtx[0] = txNew; // 放入创币交易
        pblocktemplate->vTxFees[0] = -nFees; // 计算交易手续费，为 0

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash(); // 获取父区块哈希
        UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev); 
        pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus()); // 获取难度对应值
        pblock->nNonce         = 0; // 随机数置 0，即从 0 开始找块
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]); // 获取创币交易签名操作数

        CValidationState state;
        if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) { // 验证区块是否有效
            throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
        }
    }

    return pblocktemplate.release(); // 释放并返回区块模板指针
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock; // 保证只初始化一次
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce; // 随机数加 1
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(pblock->vtx[0]); // 创建一笔可变的创币交易
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS; // 构建交易输入签名脚本
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = txCoinbase; // 把创币交易加入交易列表
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock); // 计算交易列表的默尔克树根哈希，即创币交易的 id
}

//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
// 内部矿工

//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// The nonce is usually preserved between calls, but periodically or if the
// nonce is 0xffff0000 or above, the block is rebuilt and nNonce starts over at
// zero.
// ScanHash 扫描随机数来寻找一个至少有一些 0 位的散列。随机数通常在调用间保留，如果随机数等于或超过 0xffff0000，重建区块并重置随机数为 0。
bool static ScanHash(const CBlockHeader *pblock, uint32_t& nNonce, uint256 *phash) // 挖矿算法
{
    // Write the first 76 bytes of the block header to a double-SHA256 state.
    CHash256 hasher; // 对区块头前 76 字节（不含随机数）到一个 DSHA256 状态。
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *pblock; // 导入区块头数据（80 字节）
    assert(ss.size() == 80); // BlockHeader Size: 80 Bytes
    hasher.Write((unsigned char*)&ss[0], 76); // 写入前 5 个字段（nVersion、hashPrevBlock、hashMerkleRoot、nTime、nBits），最后一个字段 nNonce 作为变量

    while (true) {
        nNonce++; // 递增随机数，每次加 1

        // Write the last 4 bytes of the block header (the nonce) to a copy of
        // the double-SHA256 state, and compute the result. // 写入随机数并进行 DSHA256
        CHash256(hasher).Write((unsigned char*)&nNonce, 4).Finalize((unsigned char*)phash);

        // Return the nonce if the hash has at least some zero bits,
        // caller will check if it has enough to reach the target
        if (((uint16_t*)phash)[15] == 0) // 共 32 字节，最后一个元素（2 个字节）为 0，即最后 16 位为 0，则返回
            return true; // 至少最后有 4 个 16 进制的 0 才返回该随机数，减少和难度目标值的比较次数

        // If nothing found after trying for a while, return -1
        if ((nNonce & 0xfff) == 0)
            return false;
    }
}

static bool ProcessBlockFound(const CBlock* pblock, const CChainParams& chainparams)
{
    LogPrintf("%s\n", pblock->ToString()); // 记录区块哈希、区块头 6 项、交易数、每笔交易详细信息到日志
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue)); // 记录创币交易产生币的数量

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash()) // 验证新区块的父区块是否为链尖区块
            return error("BitcoinMiner: generated block is stale");
    }

    // Inform about the new block
    GetMainSignals().BlockFound(pblock->GetHash()); // 通知新区块的哈希，在 validationinterface.cpp 中定义，重置该区块的请求次数为 0

    // Process this block the same as if we had received it from another node
    CValidationState state; // 默认为有效状态
    if (!ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL)) // 处理新区块（存储新区块到本地、激活最佳链）
        return error("BitcoinMiner: ProcessNewBlock, block not accepted");

    return true;
}

void getGenesisBlock(CBlock *pblock) // 获取创世区块的基本信息（nNonce, hash, merkleroot）
{
	arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);
	printf("hashTarget: %s\n", hashTarget.ToString().c_str());
	uint256 hash;
	uint32_t nNonce = 0;
	int64_t nStart = GetTime();
	while (true) {
		if (ScanHash(pblock, nNonce, &hash))
		{
			printf("block hash: %s", hash.ToString().c_str());
		    if (UintToArith256(hash) <= hashTarget)
		    {
				printf(" true\n"
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
    SetThreadPriority(THREAD_PRIORITY_LOWEST); // 设置线程优先级，宏定义在 compat.h 中
    RenameThread("bitcoin-miner"); // 重命名线程为比特币矿工

    unsigned int nExtraNonce = 0; // Nonce: Number used once/Number once 表示该随机数只用一次

    boost::shared_ptr<CReserveScript> coinbaseScript;
    GetMainSignals().ScriptForMining(coinbaseScript); // 创币交易脚本

    try {
        // Throw an error if no script was provided.  This can happen
        // due to some internal error but also if the keypool is empty.
        // In the latter case, already the pointer is NULL.
        if (!coinbaseScript || coinbaseScript->reserveScript.empty()) // 需要创币脚本，且挖矿必须有一个钱包
            throw std::runtime_error("No coinbase script available (mining requires a wallet)");

        while (true) { // 循环挖矿
            if (chainparams.MiningRequiresPeers()) { // 区分主网、公测网和回归测试网（该网可以单机挖矿）
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.
                do {
                    bool fvNodesEmpty; // 节点列表为空的标志
                    {
                        LOCK(cs_vNodes);
                        fvNodesEmpty = vNodes.empty(); // 建立连接的节点列表是否为空
                    }
#if 1 // for debug
                    LogPrintf("fvNodesEmpty: %d\n", fvNodesEmpty);
                    LogPrintf("IsInitialBlockDownload(): %d\n", IsInitialBlockDownload());
#endif
                    if (!fvNodesEmpty && !IsInitialBlockDownload()) // 必须建立一条连接（即不能单机挖矿） 且 完成初始化块下载
                        break; // 主网和公测网必须从这里跳出才能开始挖矿
                    MilliSleep(1000); // 睡 1s
                } while (true);
            }

            //
            // Create new block
            //
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated(); // 获取内存池中交易更新的数量
            CBlockIndex* pindexPrev = chainActive.Tip(); // 获取链尖区块（即最后一块）作为新建区块的父区块

            auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(chainparams, coinbaseScript->reserveScript)); // 创建新的区块模板（区块头的默尔克树根哈希字段为空）
            if (!pblocktemplate.get())
            {
                LogPrintf("Error in BitcoinMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
                return;
            }
            CBlock *pblock = &pblocktemplate->block; // 获取区块对象
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce); // 改变创币交易的输入脚本，并计算创世区块的默尔克数根哈希

            LogPrintf("Running BitcoinMiner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
                ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

            //
            // Search // 挖矿核心
            //
            int64_t nStart = GetTime(); // 记录开始挖矿的时间
            arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits); // 设置挖当前块的难度目标值
            uint256 hash; // 保存当前块的哈希
            uint32_t nNonce = 0; // 随机数初始化置 0
            while (true) { // 挖一个块
                // Check if something found
                if (ScanHash(pblock, nNonce, &hash)) // 挖矿，hash 最后 16 位为 0 则满足条件
                {
#if 1 // for debug
					LogPrintf("Search now\n");
#endif
                    if (UintToArith256(hash) <= hashTarget) // 转化为小端模式，与难度目标值比较，判断是否为合格的块
                    { // 满足条件（小于目标值）
                        // Found a solution
                        pblock->nNonce = nNonce; // 记录当前随机数到区块头
                        assert(hash == pblock->GetHash()); // 验证一下区块的哈希

                        SetThreadPriority(THREAD_PRIORITY_NORMAL); // 提高挖矿线程优先级
                        LogPrintf("BitcoinMiner:\n");
                        LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex(), hashTarget.GetHex()); // 记录挖到区块的相关信息
                        ProcessBlockFound(pblock, chainparams); // 找一个解决方案（通知新区块、本地存储该区块并激活最佳链）
                        SetThreadPriority(THREAD_PRIORITY_LOWEST); // 重置挖矿线程优先级
                        coinbaseScript->KeepScript(); // 转调 KeepKey() 从密钥池中移除该密钥

                        // In regression test mode, stop mining after a block is found.
                        if (chainparams.MineBlocksOnDemand()) // 回归测试网，挖到一个矿后线程便中断
                            throw boost::thread_interrupted();

                        break; // 跳出，继续挖下一个块
                    }
                } // 挖到的块不满足条件

                // Check for stop or if block needs to be rebuilt
                boost::this_thread::interruption_point(); // 设置中断点
                // Regtest mode doesn't require peers
                if (vNodes.empty() && chainparams.MiningRequiresPeers()) // 用于非回归测试网无连接时
                    break; // 跳出挖矿并睡觉
                if (nNonce >= 0xffff0000) // 挖矿次数超过 0xffff0000 次，则挖矿失败
                    break; // 跳出，重新建块（更新区块）挖矿
                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60) // 当前内存池交易更新的数量不等于新建区块前内存池交易更新的数量 且 挖一个矿的时间超过 60s
                    break; // 跳出，更新区块再挖矿
                if (pindexPrev != chainActive.Tip()) // 当前区块链尖改变，即有人挖到块并广播验证加入区块链
                    break; // 跳出，更新区块再挖矿

                // Update nTime every few seconds
                if (UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev) < 0) // 更新区块时间，并返回更新的时间差（测试网中会更改 nBits）
                    break; // Recreate the block if the clock has run backwards, // 如果时钟不准（落后），会跳出并重建区块
                           // so that we can use the correct time.
                if (chainparams.GetConsensus().fPowAllowMinDifficultyBlocks) // 在测试网中会重设难度目标值
                {
                    // Changing pblock->nTime can change work required on testnet:
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
    static boost::thread_group* minerThreads = NULL; // 矿工线程组指针对象

    if (nThreads < 0) // 若设置线程数小于 0
        nThreads = GetNumCores(); // 获取 CPU 核数作为挖矿线程数

    if (minerThreads != NULL) // 保证线程组指针为空，若当前已经有挖矿线程，则停止当前线程
    {
        minerThreads->interrupt_all(); // 中断线程组中的所有线程
        delete minerThreads; // 删除并置空
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate) // 验证参数（线程数和挖矿标志）
        return;

    minerThreads = new boost::thread_group(); // 创建空的矿工线程组
    for (int i = 0; i < nThreads; i++) // 创建指定线程数 nThreads 个比特币矿工线程 BitcoinMiner
        minerThreads->create_thread(boost::bind(&BitcoinMiner, boost::cref(chainparams)));
}
