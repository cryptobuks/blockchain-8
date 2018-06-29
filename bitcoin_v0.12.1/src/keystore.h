// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEYSTORE_H
#define BITCOIN_KEYSTORE_H

#include "key.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "sync.h"

#include <boost/signals2/signal.hpp>
#include <boost/variant.hpp>

/** A virtual base class for key stores */
class CKeyStore // 一个密钥仓库的虚基类
{
protected:
    mutable CCriticalSection cs_KeyStore;

public:
    virtual ~CKeyStore() {} // 虚析构

    //! Add a key to the store. // 添加一个密钥到仓库
    virtual bool AddKeyPubKey(const CKey &key, const CPubKey &pubkey) =0; // 添加私钥和公钥到仓库
    virtual bool AddKey(const CKey &key); // 添加私钥到仓库

    //! Check whether a key corresponding to a given address is present in the store. // 检查仓库中是否存在与给定地址对应的密钥
    virtual bool HaveKey(const CKeyID &address) const =0; // 仓库中是否有该地址私钥
    virtual bool GetKey(const CKeyID &address, CKey& keyOut) const =0; // 通过地址索引获取对应的私钥
    virtual void GetKeys(std::set<CKeyID> &setAddress) const =0; // 获取私钥集
    virtual bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const =0; // 通过地址索引获取公钥

    //! Support for BIP 0013 : see https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
    virtual bool AddCScript(const CScript& redeemScript) =0;
    virtual bool HaveCScript(const CScriptID &hash) const =0;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const =0;

    //! Support for Watch-only addresses // 支持 Watch-only 地址集
    virtual bool AddWatchOnly(const CScript &dest) =0; // 添加脚本到 Watch-only 集
    virtual bool RemoveWatchOnly(const CScript &dest) =0; // 从 Watch-only 集中移除该脚本
    virtual bool HaveWatchOnly(const CScript &dest) const =0; // Watch-only 集中是否有该脚本 
    virtual bool HaveWatchOnly() const =0; // 纯虚函数的实现在其派生类中
};

typedef std::map<CKeyID, CKey> KeyMap; // 密钥索引和私钥的映射
typedef std::map<CKeyID, CPubKey> WatchKeyMap; // 密钥索引和公钥的映射
typedef std::map<CScriptID, CScript > ScriptMap; // 脚本索引映射
typedef std::set<CScript> WatchOnlySet; // watch-only 脚本集合

/** Basic key store, that keeps keys in an address->secret map */
class CBasicKeyStore : public CKeyStore // 基础密钥存储，以 address->secret 映射维持私钥
{
protected:
    KeyMap mapKeys; // 私钥和索引的映射列表
    WatchKeyMap mapWatchKeys; // 公钥和索引的映射列表，用于 watch-only
    ScriptMap mapScripts; // 脚本索引映射列表
    WatchOnlySet setWatchOnly; // watch-only 脚本集合

public:
    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey);
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;
    bool HaveKey(const CKeyID &address) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapKeys.count(address) > 0);
        }
        return result;
    }
    void GetKeys(std::set<CKeyID> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.begin();
            while (mi != mapKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
    }
    bool GetKey(const CKeyID &address, CKey &keyOut) const
    {
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.find(address); // 在密钥索引和私钥映射列表中查找
            if (mi != mapKeys.end()) // 若找到指定密钥索引
            {
                keyOut = mi->second; // 获取对应的私钥
                return true;
            }
        }
        return false;
    }
    virtual bool AddCScript(const CScript& redeemScript); // 添加指定脚本
    virtual bool HaveCScript(const CScriptID &hash) const; // 脚本索引列表是否含有指定脚本
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const; // 通过脚本索引获取脚本

    virtual bool AddWatchOnly(const CScript &dest); // 添加到 watch-only 脚本集合
    virtual bool RemoveWatchOnly(const CScript &dest); // 从 watch-only 脚本集合移除
    virtual bool HaveWatchOnly(const CScript &dest) const; // 判断 watch-only 集合中是否有指定脚本
    virtual bool HaveWatchOnly() const; // watch-only 集合中是否有元素，判空
};

typedef std::vector<unsigned char, secure_allocator<unsigned char> > CKeyingMaterial; // 私钥数据
typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap; // 密钥索引对应公钥私钥对映射

#endif // BITCOIN_KEYSTORE_H
