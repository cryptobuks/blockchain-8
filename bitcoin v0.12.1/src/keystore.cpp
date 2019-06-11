// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "keystore.h"

#include "key.h"
#include "pubkey.h"
#include "util.h"

#include <boost/foreach.hpp>

bool CKeyStore::AddKey(const CKey &key) {
    return AddKeyPubKey(key, key.GetPubKey());
}

bool CBasicKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key)) {
        WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
        if (it != mapWatchKeys.end()) {
            vchPubKeyOut = it->second;
            return true;
        }
        return false;
    }
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool CBasicKeyStore::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore); // 密钥库上锁
    mapKeys[pubkey.GetID()] = key; // 加入公钥索引和私钥的映射列表
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE) // 脚本大小不能超过 520bytes
        return error("CBasicKeyStore::AddCScript(): redeemScripts > %i bytes are invalid", MAX_SCRIPT_ELEMENT_SIZE);

    LOCK(cs_KeyStore); // 密钥库上锁
    mapScripts[CScriptID(redeemScript)] = redeemScript; // 添加到脚本索引映射列表
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore); // 密钥库上锁
    return mapScripts.count(hash) > 0; // 若存在于脚本索引列表，返回 true
}

bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore); // 密钥库上锁
    ScriptMap::const_iterator mi = mapScripts.find(hash); // 查找指定脚本索引
    if (mi != mapScripts.end()) // 若找到
    {
        redeemScriptOut = (*mi).second; // 获取索引对应脚本
        return true;
    }
    return false;
}

static bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
{
    //TODO: Use Solver to extract this?
    CScript::const_iterator pc = dest.begin();
    opcodetype opcode;
    std::vector<unsigned char> vch;
    if (!dest.GetOp(pc, opcode, vch) || vch.size() < 33 || vch.size() > 65)
        return false;
    pubKeyOut = CPubKey(vch);
    if (!pubKeyOut.IsFullyValid())
        return false;
    if (!dest.GetOp(pc, opcode, vch) || opcode != OP_CHECKSIG || dest.GetOp(pc, opcode, vch))
        return false;
    return true;
}

bool CBasicKeyStore::AddWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore); // 密钥库上锁
    setWatchOnly.insert(dest); // 加入 watch-only 脚本集合
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey)) // 从脚本中提取公钥
        mapWatchKeys[pubKey.GetID()] = pubKey; // 添加到公钥索引映射列表
    return true;
}

bool CBasicKeyStore::RemoveWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore); // 密钥库上锁
    setWatchOnly.erase(dest); // 从 watch-only 脚本集合中擦除指定脚本
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey)) // 从脚本中提取公钥
        mapWatchKeys.erase(pubKey.GetID()); // 通过公钥索引从公钥索引列表中擦除该项
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore); // 密钥库上锁
    return setWatchOnly.count(dest) > 0; // 若集合中存在指定脚本，返回 true
}

bool CBasicKeyStore::HaveWatchOnly() const
{
    LOCK(cs_KeyStore); // 密钥库上锁
    return (!setWatchOnly.empty()); // 判空，非空返回 true
}
