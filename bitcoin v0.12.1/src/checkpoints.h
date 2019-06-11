// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKPOINTS_H
#define BITCOIN_CHECKPOINTS_H

#include "uint256.h"

#include <map>

class CBlockIndex;
struct CCheckpointData;

/**
 * Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */ // 区块链检测点是在编译中进行完整性检查的。每个版本或隔一个版本会更新。
namespace Checkpoints
{

//! Return conservative estimate of total number of blocks, 0 if unknown // 返回保守估计的总区块数，如果未知则返回 0
int GetTotalBlocksEstimate(const CCheckpointData& data);

//! Returns last CBlockIndex* in mapBlockIndex that is a checkpoint // 返回区块索引映射列表中作为检测点的最后一个区块索引
CBlockIndex* GetLastCheckpoint(const CCheckpointData& data);

double GuessVerificationProgress(const CCheckpointData& data, CBlockIndex* pindex, bool fSigchecks = true);

} //namespace Checkpoints

#endif // BITCOIN_CHECKPOINTS_H
