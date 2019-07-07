// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"

using namespace std;

/**
 * CChain implementation
 */ // ����Ա����ʵ��
void CChain::SetTip(CBlockIndex *pindex) {
    if (pindex == NULL) { // ����������Ϊ��
        vChain.clear(); // ������������б�
        return; // ���ؿ�
    }
    vChain.resize(pindex->nHeight + 1); // Ԥ���ٸ߶ȼ� 1 ����С�������������������飩
    while (pindex && vChain[pindex->nHeight] != pindex) { // �������������ڣ��������б�ָ���߶ȵ����������ڸ�����
        vChain[pindex->nHeight] = pindex; // ���������б�
        pindex = pindex->pprev; // ָ��ǰһ����������
    }
}

CBlockLocator CChain::GetLocator(const CBlockIndex *pindex) const { // NULL
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32); // Ԥ���� 32 ���ռ�

    if (!pindex) // NULL
        pindex = Tip(); // ��ȡ������������
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block. // ��������ӹ�����������ֹͣ��
        if (pindex->nHeight == 0) // ���߶�Ϊ 0
            break; // ֱ������
        // Exponentially larger steps back, plus the genesis block. // ����Ĳ��裬���ϴ������顣
        int nHeight = std::max(pindex->nHeight - nStep, 0);
        if (Contains(pindex)) {
            // Use O(1) CChain index if possible. // ������ܣ�ʹ����������
            pindex = (*this)[nHeight];
        } else {
            // Otherwise, use O(log n) skiplist. // ����ʹ������
            pindex = pindex->GetAncestor(nHeight);
        }
        if (vHave.size() > 10)
            nStep *= 2;
    }

    return CBlockLocator(vHave); // ��װ������λ����ʱ���󲢷���
}

const CBlockIndex *CChain::FindFork(const CBlockIndex *pindex) const {
    if (pindex == NULL) {
        return NULL;
    }
    if (pindex->nHeight > Height()) // ��ָ������߶ȴ��ڵ�ǰ�������߶�
        pindex = pindex->GetAncestor(Height()); // ��ȡ��������������
    while (pindex && !Contains(pindex)) // ������������ڼ�������ʱ���ҵ��÷�֧�Ľ���
        pindex = pindex->pprev;
    return pindex;
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); } // ��һ�������������λ�� '1' ת��Ϊ '0'

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable, // ȷ��Ҫ���صĸ߶ȡ��κ��ϸ���ڸ߶ȵ������ɽ��ܣ�
    // but the following expression seems to perform well in simulations (max 110 steps to go back // ������ı��ʽ�ƺ���ģ���б��ֵúܺá������ 110 �����ص� 2**18 �飩
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height); // height ��ǰż��
}

CBlockIndex* CBlockIndex::GetAncestor(int height) // ��ǰ�������߶�
{
    if (height > nHeight || height < 0) // �߶���֤
        return NULL;

    CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight; // ָ������ĸ߶�
    while (heightWalk > height) { // ��ָ������ĸ߶ȴ��ڵ�ǰ�������߶�
        int heightSkip = GetSkipHeight(heightWalk); // ��ȡҪ���صĸ߶�
        int heightSkipPrev = GetSkipHeight(heightWalk - 1); // ��ȡҪ���ص�ǰһ���߶�
        if (pindexWalk->pskip != NULL &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            pindexWalk = pindexWalk->pprev;
            heightWalk--; // �߶ȼ� 1
        }
    }
    return pindexWalk;
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex*>(this)->GetAncestor(height); // ת�����صĻ�ȡ�������Ⱥ���
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}
