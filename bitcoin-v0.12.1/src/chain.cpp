// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"

using namespace std;

/**
 * CChain implementation
 */ // 链成员函数实现
void CChain::SetTip(CBlockIndex *pindex) {
    if (pindex == NULL) { // 若给定索引为空
        vChain.clear(); // 清空区块索引列表
        return; // 返回空
    }
    vChain.resize(pindex->nHeight + 1); // 预开辟高度加 1 个大小的链索引（含创世区块）
    while (pindex && vChain[pindex->nHeight] != pindex) { // 若给定索引存在，且索引列表指定高度的索引不等于该索引
        vChain[pindex->nHeight] = pindex; // 放入索引列表
        pindex = pindex->pprev; // 指向前一个区块索引
    }
}

CBlockLocator CChain::GetLocator(const CBlockIndex *pindex) const { // NULL
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32); // 预开辟 32 个空间

    if (!pindex) // NULL
        pindex = Tip(); // 获取链尖区块索引
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block. // 当我们添加过创世区块后就停止。
        if (pindex->nHeight == 0) // 若高度为 0
            break; // 直接跳出
        // Exponentially larger steps back, plus the genesis block. // 更大的步骤，加上创世区块。
        int nHeight = std::max(pindex->nHeight - nStep, 0);
        if (Contains(pindex)) {
            // Use O(1) CChain index if possible. // 如果可能，使用链索引。
            pindex = (*this)[nHeight];
        } else {
            // Otherwise, use O(log n) skiplist. // 否则，使用跳表。
            pindex = pindex->GetAncestor(nHeight);
        }
        if (vHave.size() > 10)
            nStep *= 2;
    }

    return CBlockLocator(vHave); // 包装成区块位置临时对象并返回
}

const CBlockIndex *CChain::FindFork(const CBlockIndex *pindex) const {
    if (pindex == NULL) {
        return NULL;
    }
    if (pindex->nHeight > Height()) // 若指定区块高度大于当前激活链高度
        pindex = pindex->GetAncestor(Height()); // 获取其祖先区块索引
    while (pindex && !Contains(pindex)) // 当该区块包含在激活链上时，找到该分支的交点
        pindex = pindex->pprev;
    return pindex;
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); } // 把一个数二进制最低位的 '1' 转换为 '0'

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable, // 确定要跳回的高度。任何严格低于高度的数均可接受，
    // but the following expression seems to perform well in simulations (max 110 steps to go back // 但下面的表达式似乎在模拟中表现得很好。（最大 110 步返回到 2**18 块）
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height); // height 奇前偶后
}

CBlockIndex* CBlockIndex::GetAncestor(int height) // 当前激活链高度
{
    if (height > nHeight || height < 0) // 高度验证
        return NULL;

    CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight; // 指定区块的高度
    while (heightWalk > height) { // 当指定区块的高度大于当前激活链高度
        int heightSkip = GetSkipHeight(heightWalk); // 获取要跳回的高度
        int heightSkipPrev = GetSkipHeight(heightWalk - 1); // 获取要跳回的前一个高度
        if (pindexWalk->pskip != NULL &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            pindexWalk = pindexWalk->pprev;
            heightWalk--; // 高度减 1
        }
    }
    return pindexWalk;
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex*>(this)->GetAncestor(height); // 转调重载的获取区块祖先函数
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}
