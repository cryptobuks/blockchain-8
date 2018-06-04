// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Why base-58 instead of standard base-64 encoding?
 * - Don't want 0OIl characters that look the same in some fonts and
 *      could be used to create visually identical looking data.
 * - A string with non-alphanumeric characters is not as easily accepted as input.
 * - E-mail usually won't line-break if there's no punctuation to break at.
 * - Double-clicking selects the whole string as one word if it's all alphanumeric.
 */
#ifndef BITCOIN_BASE58_H
#define BITCOIN_BASE58_H

#include "chainparams.h"
#include "key.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "support/allocators/zeroafterfree.h"

#include <string>
#include <vector>

/**
 * Encode a byte sequence as a base58-encoded string.
 * pbegin and pend cannot be NULL, unless both are.
 */
std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend);

/**
 * Encode a byte vector as a base58-encoded string
 */
std::string EncodeBase58(const std::vector<unsigned char>& vch);

/**
 * Decode a base58-encoded string (psz) into a byte vector (vchRet).
 * return true if decoding is successful.
 * psz cannot be NULL.
 */
bool DecodeBase58(const char* psz, std::vector<unsigned char>& vchRet);

/**
 * Decode a base58-encoded string (str) into a byte vector (vchRet).
 * return true if decoding is successful.
 */
bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet);

/**
 * Encode a byte vector into a base58-encoded string, including checksum
 */
std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn);

/**
 * Decode a base58-encoded string (psz) that includes a checksum into a byte
 * vector (vchRet), return true if decoding is successful
 */
inline bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet);

/**
 * Decode a base58-encoded string (str) that includes a checksum into a byte
 * vector (vchRet), return true if decoding is successful
 */
inline bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet);

/**
 * Base class for all base58-encoded data
 */ // 所有 base58 编码数据的基类
class CBase58Data // 包含一个版本号和一个编码
{
protected:
    //! the version byte(s)
    std::vector<unsigned char> vchVersion; // 对于公钥地址，对应公钥地址前缀

    //! the actually encoded data
    typedef std::vector<unsigned char, zero_after_free_allocator<unsigned char> > vector_uchar;
    vector_uchar vchData; // 实际编码后的数据

    CBase58Data();
    void SetData(const std::vector<unsigned char> &vchVersionIn, const void* pdata, size_t nSize);
    void SetData(const std::vector<unsigned char> &vchVersionIn, const unsigned char *pbegin, const unsigned char *pend);

public:
    bool SetString(const char* psz, unsigned int nVersionBytes = 1);
    bool SetString(const std::string& str);
    std::string ToString() const; // 为要编码的数据附加前缀，通过该值计算两次 sha256 后取 4 bytes 的前缀附加在该值后面，再进行 Base58 编码得到公钥地址
    int CompareTo(const CBase58Data& b58) const;

    bool operator==(const CBase58Data& b58) const { return CompareTo(b58) == 0; }
    bool operator<=(const CBase58Data& b58) const { return CompareTo(b58) <= 0; }
    bool operator>=(const CBase58Data& b58) const { return CompareTo(b58) >= 0; }
    bool operator< (const CBase58Data& b58) const { return CompareTo(b58) <  0; }
    bool operator> (const CBase58Data& b58) const { return CompareTo(b58) >  0; }
};

/** base58-encoded Bitcoin addresses.
 * Public-key-hash-addresses have version 0 (or 111 testnet).
 * The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
 * Script-hash-addresses have version 5 (or 196 testnet).
 * The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
 */ // base58 编码的比特币地址
class CBitcoinAddress : public CBase58Data {
public:
    bool Set(const CKeyID &id);
    bool Set(const CScriptID &id);
    bool Set(const CTxDestination &dest);
    bool IsValid() const; // 转调下面的重载函数
    bool IsValid(const CChainParams &params) const; // 验证地址是否有效

    CBitcoinAddress() {}
    CBitcoinAddress(const CTxDestination &dest) { Set(dest); }
    CBitcoinAddress(const std::string& strAddress) { SetString(strAddress); }
    CBitcoinAddress(const char* pszAddress) { SetString(pszAddress); }

    CTxDestination Get() const; // 获取公钥索引或脚本索引
    bool GetKeyID(CKeyID &keyID) const;
    bool IsScript() const;
};

/**
 * A base58-encoded secret key
 */ // 一个 base58 编码的密钥
class CBitcoinSecret : public CBase58Data
{
public:
    void SetKey(const CKey& vchSecret);
    CKey GetKey(); // 获取私钥
    bool IsValid() const;
    bool SetString(const char* pszSecret);
    bool SetString(const std::string& strSecret); // 把 strSecret 转化为 C 风格，转调上面的重载函数

    CBitcoinSecret(const CKey& vchSecret) { SetKey(vchSecret); }
    CBitcoinSecret() {}
};

template<typename K, int Size, CChainParams::Base58Type Type> class CBitcoinExtKeyBase : public CBase58Data
{
public:
    void SetKey(const K &key) {
        unsigned char vch[Size];
        key.Encode(vch);
        SetData(Params().Base58Prefix(Type), vch, vch+Size);
    }

    K GetKey() {
        K ret;
        if (vchData.size() == Size) {
            //if base58 encouded data not holds a ext key, return a !IsValid() key
            ret.Decode(&vchData[0]);
        }
        return ret;
    }

    CBitcoinExtKeyBase(const K &key) {
        SetKey(key);
    }

    CBitcoinExtKeyBase(const std::string& strBase58c) {
        SetString(strBase58c.c_str(), Params().Base58Prefix(Type).size());
    }

    CBitcoinExtKeyBase() {}
};

typedef CBitcoinExtKeyBase<CExtKey, 74, CChainParams::EXT_SECRET_KEY> CBitcoinExtKey;
typedef CBitcoinExtKeyBase<CExtPubKey, 74, CChainParams::EXT_PUBLIC_KEY> CBitcoinExtPubKey;

#endif // BITCOIN_BASE58_H
