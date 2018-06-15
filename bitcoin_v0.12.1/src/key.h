// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEY_H
#define BITCOIN_KEY_H

#include "pubkey.h"
#include "serialize.h"
#include "support/allocators/secure.h"
#include "uint256.h"

#include <stdexcept>
#include <vector>


/** 
 * secp256k1:
 * const unsigned int PRIVATE_KEY_SIZE = 279;
 * const unsigned int PUBLIC_KEY_SIZE  = 65;
 * const unsigned int SIGNATURE_SIZE   = 72;
 *
 * see www.keylength.com
 * script supports up to 75 for single byte push
 */

/**
 * secure_allocator is defined in allocators.h
 * CPrivKey is a serialized private key, with all parameters included (279 bytes)
 */ // CPrivKey 是一个序列化的私钥，包含所有参数（279 字节）
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CPrivKey; // 拥有安全空间配置器的序列化私钥

/** An encapsulated private key. */
class CKey // 一个封装的私钥
{
private:
    //! Whether this private key is valid. We check for correctness when modifying the key
    //! data, so fValid should always correspond to the actual state.
    bool fValid; // 该私钥是否有效。我们在修改私钥数据是检查正确性，所以该标志应该总是对应实际的状态。

    //! Whether the public key corresponding to this private key is (to be) compressed.
    bool fCompressed; // 该私钥对应的公钥是否被压缩。

    //! The actual byte data
    unsigned char vch[32]; // 真正的私钥数据

    //! Check whether the 32-byte array pointed to be vch is valid keydata.
    bool static Check(const unsigned char* vch); // 检查 32 字节的数组 vch 是否为有效的私钥数据

public:
    //! Construct an invalid private key. // 构建一个无效的私钥。
    CKey() : fValid(false), fCompressed(false)
    {
        LockObject(vch);
    }

    //! Copy constructor. This is necessary because of memlocking. // 复制构造函数功能。因为内存锁这是必要的。
    CKey(const CKey& secret) : fValid(secret.fValid), fCompressed(secret.fCompressed)
    {
        LockObject(vch);
        memcpy(vch, secret.vch, sizeof(vch));
    }

    //! Destructor (again necessary because of memlocking). // 析构（因为内存锁所以是必要的）
    ~CKey()
    {
        UnlockObject(vch);
    }

    friend bool operator==(const CKey& a, const CKey& b) // 判断相对的运算符友元函数
    {
        return a.fCompressed == b.fCompressed && a.size() == b.size() &&
               memcmp(&a.vch[0], &b.vch[0], a.size()) == 0;
    }

    //! Initialize using begin and end iterators to byte data.
    template <typename T> // 使用首尾迭代器指定的数据初始化私钥
    void Set(const T pbegin, const T pend, bool fCompressedIn)
    {
        if (pend - pbegin != 32) {
            fValid = false;
            return;
        }
        if (Check(&pbegin[0])) {
            memcpy(vch, (unsigned char*)&pbegin[0], 32);
            fValid = true;
            fCompressed = fCompressedIn;
        } else {
            fValid = false;
        }
    }

    //! Simple read-only vector-like interface.
    unsigned int size() const { return (fValid ? 32 : 0); }
    const unsigned char* begin() const { return vch; }
    const unsigned char* end() const { return vch + size(); }

    //! Check whether this private key is valid.
    bool IsValid() const { return fValid; } // 检查私钥是否有效。

    //! Check whether the public key corresponding to this private key is (to be) compressed.
    bool IsCompressed() const { return fCompressed; } // 检查该私钥对应公钥是否被压缩。

    //! Initialize from a CPrivKey (serialized OpenSSL private key data).
    bool SetPrivKey(const CPrivKey& vchPrivKey, bool fCompressed); // 从 CPrivKey（序列化的 OpenSSL 私钥数据）初始化私钥

    //! Generate a new private key using a cryptographic PRNG.
    void MakeNewKey(bool fCompressed); // 随机生成一个 256 位的私钥

    /**
     * Convert the private key to a CPrivKey (serialized OpenSSL private key data).
     * This is expensive. 
     */ // 转换私钥为一个 CPrivKey。代价很高。
    CPrivKey GetPrivKey() const;

    /**
     * Compute the public key from a private key.
     * This is expensive.
     */ // 从一个私钥计算公钥。代价很高。
    CPubKey GetPubKey() const;

    /**
     * Create a DER-serialized signature.
     * The test_case parameter tweaks the deterministic nonce.
     */
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig, uint32_t test_case = 0) const;

    /**
     * Create a compact signature (65 bytes), which allows reconstructing the used public key.
     * The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
     * The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
     *                  0x1D = second key with even y, 0x1E = second key with odd y,
     *                  add 0x04 for compressed keys.
     */ // 创建一个紧凑型的签名消息（65 字节），它允许重建使用的公钥。
    bool SignCompact(const uint256& hash, std::vector<unsigned char>& vchSig) const;

    //! Derive BIP32 child key.
    bool Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const;

    /**
     * Verify thoroughly whether a private key and a public key match.
     * This is done using a different mechanism than just regenerating it.
     */ // 彻底验证私钥和公钥是否匹配。这里使用了一个不同的机制而不仅仅再生成一遍。
    bool VerifyPubKey(const CPubKey& vchPubKey) const;

    //! Load private key and check that public key matches. // 加载私钥并检查公钥是否匹配
    bool Load(CPrivKey& privkey, CPubKey& vchPubKey, bool fSkipCheck);

    //! Check whether an element of a signature (r or s) is valid.
    static bool CheckSignatureElement(const unsigned char* vch, int len, bool half); // 检查一个签名元素是否有效
};

struct CExtKey {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    ChainCode chaincode;
    CKey key;

    friend bool operator==(const CExtKey& a, const CExtKey& b)
    {
        return a.nDepth == b.nDepth && memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], 4) == 0 && a.nChild == b.nChild &&
               a.chaincode == b.chaincode && a.key == b.key;
    }

    void Encode(unsigned char code[74]) const;
    void Decode(const unsigned char code[74]);
    bool Derive(CExtKey& out, unsigned int nChild) const;
    CExtPubKey Neuter() const;
    void SetMaster(const unsigned char* seed, unsigned int nSeedLen);
};

/** Initialize the elliptic curve support. May not be called twice without calling ECC_Stop first. */
void ECC_Start(void);

/** Deinitialize the elliptic curve support. No-op if ECC_Start wasn't called first. */
void ECC_Stop(void);

/** Check that required EC support is available at runtime. */
bool ECC_InitSanityCheck(void);

#endif // BITCOIN_KEY_H
