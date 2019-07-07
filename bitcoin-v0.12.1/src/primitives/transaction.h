// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include "amount.h"
#include "script/script.h"
#include "serialize.h"
#include "uint256.h"

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint // ���ڽ��׵����� CTxIn �У�ȷ�ϵ�ǰ�������Դ
{
public:
    uint256 hash; // һ�ʽ��׵Ĺ�ϣ
    uint32_t n; // һ�ʽ��׵�����/��������кţ����� n �����

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, uint32_t nIn) { hash = hashIn; n = nIn; }

    ADD_SERIALIZE_METHODS; // ���л����ݽṹ������洢�ʹ���

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(hash);
        READWRITE(n);
    }

    void SetNull() { hash.SetNull(); n = (uint32_t) -1; }
    bool IsNull() const { return (hash.IsNull() && n == (uint32_t) -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b) // ���������
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */ // һ�ʽ��׵����롣������ǰһ�ʽ��������λ�ú��������Կƥ���ǩ����
class CTxIn
{
public:
    COutPoint prevout; // ǰһ�ʽ��׵����
    CScript scriptSig; // ƥ�������Կ�Ľű�ǩ��
    uint32_t nSequence; // ���к�

    /* Setting nSequence to this value for every input in a transaction
     * disables nLockTime. */ // ���� 1��һ�ʽ����е�ÿ����������кŶ������˸�ֵ���ý��׵� nLockTime ����ֹ
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68*/
    /* If this flag set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time. */ // ���� 2����������˸ñ�־������ 1 ʧЧ
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31);

    /* If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */ // ���� 3��������� 1 ��Ч�������˴˱��������������ʱ���� 512 �룬��������ʱ��Ϊһ������
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /* If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */ // ���� 4��������� 1 ��Ч����ñ��������� nSequence ������Ե�����ʱ��
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /* In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL); // explicit ������ʽת���������캯������ʹ�õ�ǰ��ʽ
    CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(prevout);
        READWRITE(*(CScriptBase*)(&scriptSig));
        READWRITE(nSequence);
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut // һ�ʽ��׵����
{
public:
    CAmount nValue; // ����Ľ��
    CScript scriptPubKey; // ������Ĺ�Կ�ű��������ű���

    CTxOut()
    {
        SetNull();
    }

    CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nValue);
        READWRITE(*(CScriptBase*)(&scriptPubKey));
    }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    uint256 GetHash() const;

    CAmount GetDustThreshold(const CFeeRate &minRelayTxFee) const // ��ȡ dust ��ֵ��
    { // һ�ʽ��׵Ľ��׷���С�� dust ��ֵ���򱻵��� dust tx���˺������°���ת�Ƶ� src/policy/policy.cpp
        // "Dust" is defined in terms of CTransaction::minRelayTxFee,
        // which has units satoshis-per-kilobyte.
        // If you'd pay more than 1/3 in fees
        // to spend something, then we consider it dust.
        // A typical spendable txout is 34 bytes big, and will
        // need a CTxIn of at least 148 bytes to spend:
        // so dust is a spendable txout less than
        // 546*minRelayTxFee/1000 (in satoshis)
        if (scriptPubKey.IsUnspendable()) // �жϽű���ʽ�Ƿ���ȷ
            return 0;

        size_t nSize = GetSerializeSize(SER_DISK,0)+148u;
        return 3*minRelayTxFee.GetFee(nSize);
    } // ���ã���ֹ�۳�������������С���ӿ�������������������Ľ��׳ٳٱ����

    bool IsDust(const CFeeRate &minRelayTxFee) const // �ж��Ƿ�Ϊ�۳�����
    {
        return (nValue < GetDustThreshold(minRelayTxFee));
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

struct CMutableTransaction;

/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction // �ý���Ϊ���ױ�汾��һ�����ɲ��ܸı䣨�����й㲥����������
{
private:
    /** Memory only. */
    const uint256 hash; // ���׹�ϣ
    void UpdateHash() const;

public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION=1; // Ĭ�Ͻ��װ汾

    // Changing the default transaction version requires a two step process: first
    // adapting relay policy by bumping MAX_STANDARD_VERSION, and then later date
    // bumping the default CURRENT_VERSION at which point both CURRENT_VERSION and
    // MAX_STANDARD_VERSION will be equal.
    static const int32_t MAX_STANDARD_VERSION=2;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const int32_t nVersion; // ���װ汾
    const std::vector<CTxIn> vin; // ���������б�
    const std::vector<CTxOut> vout; // ��������б�
    const uint32_t nLockTime; // ����ʱ��

    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction(); // ����һ�ʷ��� IsNull() �Ľ���

    /** Convert a CMutableTransaction into a CTransaction. */
    CTransaction(const CMutableTransaction &tx);

    CTransaction& operator=(const CTransaction& tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*const_cast<int32_t*>(&this->nVersion));
        nVersion = this->nVersion;
        READWRITE(*const_cast<std::vector<CTxIn>*>(&vin));
        READWRITE(*const_cast<std::vector<CTxOut>*>(&vout));
        READWRITE(*const_cast<uint32_t*>(&nLockTime));
        if (ser_action.ForRead())
            UpdateHash();
    }

    bool IsNull() const { // �����������ǿ�
        return vin.empty() && vout.empty();
    }

    const uint256& GetHash() const { // ��ȡ�����׹�ϣ
        return hash;
    }

    // Return sum of txouts.
    CAmount GetValueOut() const; // ���ؽ�������ܺ�
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    // Compute priority, given priority of inputs and (optionally) tx size // �������ȼ���������������ȼ��ͣ���ѡ�ģ����״�С
    double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const;

    // Compute modified tx size for priority calculation (optionally given tx size)
    unsigned int CalculateModifiedSize(unsigned int nTxSize=0) const;

    bool IsCoinBase() const // �ж��Ƿ�Ϊ���ҽ���
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return a.hash == b.hash;
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return a.hash != b.hash;
    }

    std::string ToString() const; // ���������Ϣ
};

/** A mutable version of CTransaction. */
struct CMutableTransaction // �ױ�汾���ף������ɺ�ɸ���
{
    int32_t nVersion; // �汾��
    std::vector<CTxIn> vin; // �����б�
    std::vector<CTxOut> vout; // ����б�
    uint32_t nLockTime; // ����ʱ��

    CMutableTransaction();
    CMutableTransaction(const CTransaction& tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    uint256 GetHash() const;
};

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
