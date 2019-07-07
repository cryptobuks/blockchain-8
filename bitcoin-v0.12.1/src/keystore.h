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
class CKeyStore // һ����Կ�ֿ�������
{
protected:
    mutable CCriticalSection cs_KeyStore;

public:
    virtual ~CKeyStore() {} // ������

    //! Add a key to the store. // ���һ����Կ���ֿ�
    virtual bool AddKeyPubKey(const CKey &key, const CPubKey &pubkey) =0; // ���˽Կ�͹�Կ���ֿ�
    virtual bool AddKey(const CKey &key); // ���˽Կ���ֿ�

    //! Check whether a key corresponding to a given address is present in the store. // ���ֿ����Ƿ�����������ַ��Ӧ����Կ
    virtual bool HaveKey(const CKeyID &address) const =0; // �ֿ����Ƿ��иõ�ַ˽Կ
    virtual bool GetKey(const CKeyID &address, CKey& keyOut) const =0; // ͨ����ַ������ȡ��Ӧ��˽Կ
    virtual void GetKeys(std::set<CKeyID> &setAddress) const =0; // ��ȡ˽Կ��
    virtual bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const =0; // ͨ����ַ������ȡ��Կ

    //! Support for BIP 0013 : see https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
    virtual bool AddCScript(const CScript& redeemScript) =0;
    virtual bool HaveCScript(const CScriptID &hash) const =0;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const =0;

    //! Support for Watch-only addresses // ֧�� Watch-only ��ַ��
    virtual bool AddWatchOnly(const CScript &dest) =0; // ��ӽű��� Watch-only ��
    virtual bool RemoveWatchOnly(const CScript &dest) =0; // �� Watch-only �����Ƴ��ýű�
    virtual bool HaveWatchOnly(const CScript &dest) const =0; // Watch-only �����Ƿ��иýű� 
    virtual bool HaveWatchOnly() const =0; // ���麯����ʵ��������������
};

typedef std::map<CKeyID, CKey> KeyMap; // ��Կ������˽Կ��ӳ��
typedef std::map<CKeyID, CPubKey> WatchKeyMap; // ��Կ�����͹�Կ��ӳ��
typedef std::map<CScriptID, CScript > ScriptMap; // �ű�����ӳ��
typedef std::set<CScript> WatchOnlySet; // watch-only �ű�����

/** Basic key store, that keeps keys in an address->secret map */
class CBasicKeyStore : public CKeyStore // ������Կ�洢���� address->secret ӳ��ά��˽Կ
{
protected:
    KeyMap mapKeys; // ˽Կ��������ӳ���б�
    WatchKeyMap mapWatchKeys; // ��Կ��������ӳ���б����� watch-only
    ScriptMap mapScripts; // �ű�����ӳ���б�
    WatchOnlySet setWatchOnly; // watch-only �ű�����

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
            KeyMap::const_iterator mi = mapKeys.find(address); // ����Կ������˽Կӳ���б��в���
            if (mi != mapKeys.end()) // ���ҵ�ָ����Կ����
            {
                keyOut = mi->second; // ��ȡ��Ӧ��˽Կ
                return true;
            }
        }
        return false;
    }
    virtual bool AddCScript(const CScript& redeemScript); // ���ָ���ű�
    virtual bool HaveCScript(const CScriptID &hash) const; // �ű������б��Ƿ���ָ���ű�
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const; // ͨ���ű�������ȡ�ű�

    virtual bool AddWatchOnly(const CScript &dest); // ��ӵ� watch-only �ű�����
    virtual bool RemoveWatchOnly(const CScript &dest); // �� watch-only �ű������Ƴ�
    virtual bool HaveWatchOnly(const CScript &dest) const; // �ж� watch-only �������Ƿ���ָ���ű�
    virtual bool HaveWatchOnly() const; // watch-only �������Ƿ���Ԫ�أ��п�
};

typedef std::vector<unsigned char, secure_allocator<unsigned char> > CKeyingMaterial; // ˽Կ����
typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap; // ��Կ������Ӧ��Կ˽Կ��ӳ��

#endif // BITCOIN_KEYSTORE_H
