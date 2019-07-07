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
    LOCK(cs_KeyStore); // ��Կ������
    mapKeys[pubkey.GetID()] = key; // ���빫Կ������˽Կ��ӳ���б�
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE) // �ű���С���ܳ��� 520bytes
        return error("CBasicKeyStore::AddCScript(): redeemScripts > %i bytes are invalid", MAX_SCRIPT_ELEMENT_SIZE);

    LOCK(cs_KeyStore); // ��Կ������
    mapScripts[CScriptID(redeemScript)] = redeemScript; // ��ӵ��ű�����ӳ���б�
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore); // ��Կ������
    return mapScripts.count(hash) > 0; // �������ڽű������б����� true
}

bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore); // ��Կ������
    ScriptMap::const_iterator mi = mapScripts.find(hash); // ����ָ���ű�����
    if (mi != mapScripts.end()) // ���ҵ�
    {
        redeemScriptOut = (*mi).second; // ��ȡ������Ӧ�ű�
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
    LOCK(cs_KeyStore); // ��Կ������
    setWatchOnly.insert(dest); // ���� watch-only �ű�����
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey)) // �ӽű�����ȡ��Կ
        mapWatchKeys[pubKey.GetID()] = pubKey; // ��ӵ���Կ����ӳ���б�
    return true;
}

bool CBasicKeyStore::RemoveWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore); // ��Կ������
    setWatchOnly.erase(dest); // �� watch-only �ű������в���ָ���ű�
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey)) // �ӽű�����ȡ��Կ
        mapWatchKeys.erase(pubKey.GetID()); // ͨ����Կ�����ӹ�Կ�����б��в�������
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore); // ��Կ������
    return setWatchOnly.count(dest) > 0; // �������д���ָ���ű������� true
}

bool CBasicKeyStore::HaveWatchOnly() const
{
    LOCK(cs_KeyStore); // ��Կ������
    return (!setWatchOnly.empty()); // �пգ��ǿշ��� true
}
