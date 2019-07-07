// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"

#include "base58.h"
#include "checkpoints.h"
#include "chain.h"
#include "coincontrol.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "key.h"
#include "keystore.h"
#include "main.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sign.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"

#include <assert.h>

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

using namespace std;

/** Transaction fee set by the user */ // �û����õĽ��׷�
CFeeRate payTxFee(DEFAULT_TRANSACTION_FEE); // Ĭ�Ͻ��׷�Ϊ 0
CAmount maxTxFee = DEFAULT_TRANSACTION_MAXFEE; // ���׷�����Ϊ 0.1 BTC
unsigned int nTxConfirmTarget = DEFAULT_TX_CONFIRM_TARGET;
bool bSpendZeroConfChange = DEFAULT_SPEND_ZEROCONF_CHANGE;
bool fSendFreeTransactions = DEFAULT_SEND_FREE_TRANSACTIONS; // ��ѷ��ͽ��ױ�־��Ĭ��Ϊ false

/**
 * Fees smaller than this (in satoshi) are considered zero fee (for transaction creation)
 * Override with -mintxfee
 */
CFeeRate CWallet::minTxFee = CFeeRate(DEFAULT_TRANSACTION_MINFEE);
/**
 * If fee estimation does not have enough data to provide estimates, use this fee instead.
 * Has no effect if not using fee estimation
 * Override with -fallbackfee
 */
CFeeRate CWallet::fallbackFee = CFeeRate(DEFAULT_FALLBACK_FEE);

const uint256 CMerkleTx::ABANDON_HASH(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));

/** @defgroup mapWallet
 *
 * @{
 */

struct CompareValueOnly
{
    bool operator()(const pair<CAmount, pair<const CWalletTx*, unsigned int> >& t1,
                    const pair<CAmount, pair<const CWalletTx*, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};

std::string COutput::ToString() const
{
    return strprintf("COutput(%s, %d, %d) [%s]", tx->GetHash().ToString(), i, nDepth, FormatMoney(tx->vout[i].nValue));
}

const CWalletTx* CWallet::GetWalletTx(const uint256& hash) const
{
    LOCK(cs_wallet);
    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return NULL;
    return &(it->second);
}

CPubKey CWallet::GenerateNewKey()
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    CKey secret; // ����һ��˽Կ
    secret.MakeNewKey(fCompressed); // �������һ��������ʼ��˽Կ��ע��߽磬�½�Ϊ 1

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed) // �Ƿ�ѹ����Կ��0.6.0 ������
        SetMinVersion(FEATURE_COMPRPUBKEY);

    CPubKey pubkey = secret.GetPubKey(); // ��ȡ��˽Կ��Ӧ�Ĺ�Կ����Բ���߼����㷨��
    assert(secret.VerifyPubKey(pubkey)); // ��֤˽Կ��Կ���Ƿ�ƥ��

    // Create new metadata // ������Ԫ����/�м�����
    int64_t nCreationTime = GetTime(); // ��ȡ��ǰʱ��
    mapKeyMetadata[pubkey.GetID()] = CKeyMetadata(nCreationTime);
    if (!nTimeFirstKey || nCreationTime < nTimeFirstKey)
        nTimeFirstKey = nCreationTime;

    if (!AddKeyPubKey(secret, pubkey))
        throw std::runtime_error("CWallet::GenerateNewKey(): AddKey failed");
    return pubkey; // ���ض�Ӧ�Ĺ�Կ
}

bool CWallet::AddKeyPubKey(const CKey& secret, const CPubKey &pubkey)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (!CCryptoKeyStore::AddKeyPubKey(secret, pubkey))
        return false;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(pubkey.GetID());
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);
    script = GetScriptForRawPubKey(pubkey);
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);

    if (!fFileBacked)
        return true;
    if (!IsCrypted()) {
        return CWalletDB(strWalletFile).WriteKey(pubkey,
                                                 secret.GetPrivKey(),
                                                 mapKeyMetadata[pubkey.GetID()]);
    }
    return true;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey,
                            const vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey,
                                                        vchCryptedSecret,
                                                        mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey,
                                                            vchCryptedSecret,
                                                            mapKeyMetadata[vchPubKey.GetID()]);
    }
    return false;
}

bool CWallet::LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (meta.nCreateTime && (!nTimeFirstKey || meta.nCreateTime < nTimeFirstKey))
        nTimeFirstKey = meta.nCreateTime;

    mapKeyMetadata[pubkey.GetID()] = meta;
    return true;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CWallet::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = CBitcoinAddress(CScriptID(redeemScript)).ToString();
        LogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n",
            __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return CCryptoKeyStore::AddCScript(redeemScript);
}

bool CWallet::AddWatchOnly(const CScript &dest)
{
    if (!CCryptoKeyStore::AddWatchOnly(dest)) // ��� watch-only ��ַ����Կ��
        return false;
    nTimeFirstKey = 1; // No birthday information for watch-only keys. // watch-only ��Կû�д���ʱ����Ϣ��
    NotifyWatchonlyChanged(true); // ֪ͨ watch-only ��ַ�Ѹı�
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteWatchOnly(dest); // �� watch-only ��ַд��Ǯ�����ݿ��ļ���
}

bool CWallet::RemoveWatchOnly(const CScript &dest)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveWatchOnly(dest)) // ����Կ�����Ƴ� watch-only ��ַ
        return false;
    if (!HaveWatchOnly()) // ��û�� watch-only ��ַ
        NotifyWatchonlyChanged(false); // ֪ͨ watch-only ��ַ�Ѹı�
    if (fFileBacked) // ���ļ����ݿ���
        if (!CWalletDB(strWalletFile).EraseWatchOnly(dest)) // ��Ǯ�����ݿ��в��� watch-only ��ַ
            return false;

    return true;
}

bool CWallet::LoadWatchOnly(const CScript &dest) // ���� watch-only ��ַ
{
    return CCryptoKeyStore::AddWatchOnly(dest); // ֻ�� watch-only ��ַ�����ڴ��е���Կ��
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                continue; // try another master key
            if (CCryptoKeyStore::Unlock(vMasterKey))
                return true;
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked(); // ��ȡ��ǰǮ������״̬��Ϊ��ǰ����״̬

    {
        LOCK(cs_wallet); // Ǯ������
        Lock(); // ���������ܣ�Ǯ��

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys) // ��������Կӳ���б�
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod)) // �Ӿ�����������Կ
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey)) // ����
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey)) // ����
            {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod); // ʹ���������ȡ��Կ
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime))); // �����������

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod); // �� 2 ������
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2; // ���¼����������

                if (pMasterKey.second.nDeriveIterations < 25000) // ����������С 25000
                    pMasterKey.second.nDeriveIterations = 25000;

                LogPrintf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod)) // �� 3 ������
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey)) // ����
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second); // ������Կд��Ǯ�����ݿ�
                if (fWasLocked) // ������ı�ǰδ����״̬
                    Lock(); // ����������)
                return true;
            }
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(strWalletFile); // ����Ǯ�����ݿ�ֲ�����
    walletdb.WriteBestBlock(loc); // д����ѿ�λ�õ�Ǯ�����ݿ��ļ�
}

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    LOCK(cs_wallet); // nWalletVersion
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion) // ����Ǯ�����汾
{
    LOCK(cs_wallet); // nWalletVersion, nWalletMaxVersion
    // cannot downgrade below current version // ���ܽ�������ǰ�汾����
    if (nWalletVersion > nVersion) // �����ð汾���ڵ��ڵ�ǰ
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

set<uint256> CWallet::GetConflicts(const uint256& txid) const
{
    set<uint256> result;
    AssertLockHeld(cs_wallet);

    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CWalletTx& wtx = it->second;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    BOOST_FOREACH(const CTxIn& txin, wtx.vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue;  // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
            result.insert(it->second);
    }
    return result;
}

void CWallet::Flush(bool shutdown)
{
    bitdb.Flush(shutdown);
}

bool CWallet::Verify(const string& walletFile, string& warningString, string& errorString)
{
    if (!bitdb.Open(GetDataDir())) // 1.�������ݿ�ʧ��
    {
        // try moving the database env out of the way // �����ƶ����ݿ���Ŀ
        boost::filesystem::path pathDatabase = GetDataDir() / "database"; // ƴ�����ݿ�Ŀ¼
        boost::filesystem::path pathDatabaseBak = GetDataDir() / strprintf("database.%d.bak", GetTime()); // ƴ�����ݿⱸ��·��
        try {
            boost::filesystem::rename(pathDatabase, pathDatabaseBak); // ������Ϊ���ݿⱸ����������ʧ��
            LogPrintf("Moved old %s to %s. Retrying.\n", pathDatabase.string(), pathDatabaseBak.string());
        } catch (const boost::filesystem::filesystem_error&) { // ����ʧ�ܣ��ðɣ�������ģ������������ǿ�ʼʱ�㣩
            // failure is ok (well, not really, but it's not worse than what we started with)
        }
        
        // try again // ����һ��
        if (!bitdb.Open(GetDataDir())) { // �ٴδ����ݿ⣬����ʧ�ܣ�������ζ��������Ȼ�޷��������ݿ⻷��
            // if it still fails, it probably means we can't even create the database env
            string msg = strprintf(_("Error initializing wallet database environment %s!"), GetDataDir());
            errorString += msg; // ׷�Ӵ�����Ϣ
            return true; // ֱ�ӷ��� true
        }
    }
    
    if (GetBoolArg("-salvagewallet", false)) // 2.����Ǯ��ѡ�Ĭ�Ϲر�
    {
        // Recover readable keypairs: // �ָ��ɶ�����Կ�ԣ�
        if (!CWalletDB::Recover(bitdb, walletFile, true)) // �ָ��ɶ�����Կ��
            return false;
    }
    
    if (boost::filesystem::exists(GetDataDir() / walletFile)) // 3.��Ǯ���ļ�����
    {
        CDBEnv::VerifyResult r = bitdb.Verify(walletFile, CWalletDB::Recover); // ��֤Ǯ�����ݿ��ļ������ļ��쳣������лָ������ػָ��Ľ��
        if (r == CDBEnv::RECOVER_OK) // �ָ���Ϣ׷��
        {
            warningString += strprintf(_("Warning: wallet.dat corrupt, data salvaged!"
                                     " Original wallet.dat saved as wallet.{timestamp}.bak in %s; if"
                                     " your balance or transactions are incorrect you should"
                                     " restore from a backup."), GetDataDir());
        }
        if (r == CDBEnv::RECOVER_FAIL)
            errorString += _("wallet.dat corrupt, salvage failed");
    }
    
    return true; // 4.��֤�ɹ������� true
}

void CWallet::SyncMetaData(pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx* copyFrom = NULL;
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const uint256& hash = it->second;
        int n = mapWallet[hash].nOrderPos;
        if (n < nMinOrderPos)
        {
            nMinOrderPos = n;
            copyFrom = &mapWallet[hash];
        }
    }
    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const uint256& hash = it->second;
        CWalletTx* copyTo = &mapWallet[hash];
        if (copyFrom == copyTo) continue;
        if (!copyFrom->IsEquivalentTo(*copyTo)) continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        copyTo->strFromAccount = copyFrom->strFromAccount;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */ // ���κηǳ�ͻ�Ľ��׻���������㣬��ô��������Ƿ��ѻ���
bool CWallet::IsSpent(const uint256& hash, unsigned int n) const
{
    const COutPoint outpoint(hash, n);
    pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
    {
        const uint256& wtxid = it->second;
        std::map<uint256, CWalletTx>::const_iterator mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end()) {
            int depth = mit->second.GetDepthInMainChain();
            if (depth > 0  || (depth == 0 && !mit->second.isAbandoned()))
                return true; // Spent
        }
    }
    return false;
}

void CWallet::AddToSpends(const COutPoint& outpoint, const uint256& wtxid)
{
    mapTxSpends.insert(make_pair(outpoint, wtxid));

    pair<TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData(range);
}


void CWallet::AddToSpends(const uint256& wtxid)
{
    assert(mapWallet.count(wtxid));
    CWalletTx& thisTx = mapWallet[wtxid];
    if (thisTx.IsCoinBase()) // Coinbases don't spend anything!
        return;

    BOOST_FOREACH(const CTxIn& txin, thisTx.vin)
        AddToSpends(txin.prevout, wtxid);
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted()) // ���Ǯ���Ѽ���
        return false; // ֱ���˳�

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon(); // �������������

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE); // Ԥ������Կ��С
    GetRandBytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE); // ��ȡ 32 �ֽڵ�����ֽ�

    CMasterKey kMasterKey; // ����Կ����
    RandAddSeedPerfmon(); // �ٴδ������������

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE); // Ԥ��������Կ��ֵ��С
    GetRandBytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE); // ��ȡ 8 �ֽڵ�����ֽ�

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis(); // ��¼��ʼʱ��
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod); // ���û�ָ������������Կ
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime)); // �����������

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod); // �� 2 �ε��� sha512 ���м���
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2; // ���¼����������

    if (kMasterKey.nDeriveIterations < 25000) // �����������Ϊ 25000
        kMasterKey.nDeriveIterations = 25000;

    LogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod)) // �� 3 �ε��� sha512 ��ȡ��Կ�ͳ�ʼ������
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey)) // 
        return false;

    {
        LOCK(cs_wallet); // Ǯ������
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey; // ��������Կӳ��
        if (fFileBacked)
        {
            assert(!pwalletdbEncryption);
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin()) {
                delete pwalletdbEncryption;
                pwalletdbEncryption = NULL;
                return false;
            }
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey); // д����Կ��Ǯ�����ݿ�
        }

        if (!EncryptKeys(vMasterKey))
        {
            if (fFileBacked) {
                pwalletdbEncryption->TxnAbort();
                delete pwalletdbEncryption;
            } // �������ڿ�����һ����ܵ���Կ���ڴ棬��һ��δ����...
            // We now probably have half of our keys encrypted in memory, and half not...
            // die and let the user reload the unencrypted wallet. // �رղ����û����¼���δ���ܵ�Ǯ��
            assert(false);
        }

        // Encryption was introduced in version 0.4.0 // �����ڰ汾 0.4.0 ����
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked) // �ļ����ݱ�־
        {
            if (!pwalletdbEncryption->TxnCommit()) {
                delete pwalletdbEncryption;
                // We now have keys encrypted in memory, but not on disk... // ��������ӵ���ڴ��еļ�����Կ�����ڴ�����û��...
                // die to avoid confusion and let the user reload the unencrypted wallet. // ����������������û����¼���δ���ܵ�Ǯ��
                assert(false);
            }

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock(); // ��������־����״̬
        Unlock(strWalletPassphrase); // ͨ���û�ָ���������
        NewKeyPool(); // �½���Կ��
        Lock(); // �ٴ�����

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile); // ��Ҫ��ȫ��дǮ���ļ���������ǲ���ô����bdb ���ܻᱣ��δ����˽Կ����λ�����ݿ��ļ�����ɢ�ռ䡣

    }
    NotifyStatusChanged(this); // ֪ͨǮ��״̬�Ѹı�

    return true;
}

int64_t CWallet::IncOrderPosNext(CWalletDB *pwalletdb)
{
    AssertLockHeld(cs_wallet); // nOrderPosNext
    int64_t nRet = nOrderPosNext++; // ��� +1
    if (pwalletdb) { // ��Ǯ�����ݿ�������
        pwalletdb->WriteOrderPosNext(nOrderPosNext); // д�����ݿ�
    } else {
        CWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet; // �������Ӻ����һ���������
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet); // Ǯ������
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet) // ����Ǯ������ӳ���б�
            item.second.MarkDirty(); // ���Ǯ���е�ÿ�ʽ���Ϊ�ѱ䶯
    }
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn, bool fFromLoadWallet, CWalletDB* pwalletdb)
{
    uint256 hash = wtxIn.GetHash();

    if (fFromLoadWallet)
    {
        mapWallet[hash] = wtxIn;
        CWalletTx& wtx = mapWallet[hash];
        wtx.BindWallet(this);
        wtxOrdered.insert(make_pair(wtx.nOrderPos, TxPair(&wtx, (CAccountingEntry*)0)));
        AddToSpends(hash);
        BOOST_FOREACH(const CTxIn& txin, wtx.vin) {
            if (mapWallet.count(txin.prevout.hash)) {
                CWalletTx& prevtx = mapWallet[txin.prevout.hash];
                if (prevtx.nIndex == -1 && !prevtx.hashUnset()) {
                    MarkConflicted(prevtx.hashBlock, wtx.GetHash());
                }
            }
        }
    }
    else
    {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        wtx.BindWallet(this);
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
        {
            wtx.nTimeReceived = GetAdjustedTime();
            wtx.nOrderPos = IncOrderPosNext(pwalletdb);
            wtxOrdered.insert(make_pair(wtx.nOrderPos, TxPair(&wtx, (CAccountingEntry*)0)));

            wtx.nTimeSmart = wtx.nTimeReceived;
            if (!wtxIn.hashUnset())
            {
                if (mapBlockIndex.count(wtxIn.hashBlock))
                {
                    int64_t latestNow = wtx.nTimeReceived;
                    int64_t latestEntry = 0;
                    {
                        // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                        int64_t latestTolerated = latestNow + 300;
                        const TxItems & txOrdered = wtxOrdered;
                        for (TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
                        {
                            CWalletTx *const pwtx = (*it).second.first;
                            if (pwtx == &wtx)
                                continue;
                            CAccountingEntry *const pacentry = (*it).second.second;
                            int64_t nSmartTime;
                            if (pwtx)
                            {
                                nSmartTime = pwtx->nTimeSmart;
                                if (!nSmartTime)
                                    nSmartTime = pwtx->nTimeReceived;
                            }
                            else
                                nSmartTime = pacentry->nTime;
                            if (nSmartTime <= latestTolerated)
                            {
                                latestEntry = nSmartTime;
                                if (nSmartTime > latestNow)
                                    latestNow = nSmartTime;
                                break;
                            }
                        }
                    }

                    int64_t blocktime = mapBlockIndex[wtxIn.hashBlock]->GetBlockTime();
                    wtx.nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
                }
                else
                    LogPrintf("AddToWallet(): found %s in block %s not in index\n",
                             wtxIn.GetHash().ToString(),
                             wtxIn.hashBlock.ToString());
            }
            AddToSpends(hash);
        }

        bool fUpdated = false;
        if (!fInsertedNew)
        {
            // Merge
            if (!wtxIn.hashUnset() && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            // If no longer abandoned, update
            if (wtxIn.hashBlock.IsNull() && wtx.isAbandoned())
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.nIndex != wtx.nIndex))
            {
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
        }

        //// debug print
        LogPrintf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated)
            if (!wtx.WriteToDisk(pwalletdb))
                return false;

        // Break debit/credit balance caches:
        wtx.MarkDirty();

        // Notify UI of new or updated transaction
        NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

        // notify an external script when a wallet transaction comes in or is updated
        std::string strCmd = GetArg("-walletnotify", "");

        if ( !strCmd.empty())
        {
            boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
            boost::thread t(runCommand, strCmd); // thread runs free
        }

    }
    return true;
}

/**
 * Add a transaction to the wallet, or update it.
 * pblock is optional, but should be provided if the transaction is known to be in a block.
 * If fUpdate is true, existing transactions will be updated.
 */ // ���һ�ʽ��׵�Ǯ��������������pblock Ϊ��ѡ�������������֪��һ�������У�Ӧ���ṩ��ֵ����� fUpdate Ϊ true���ִ�Ľ��׽���������
bool CWallet::AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate)
{
    {
        AssertLockHeld(cs_wallet);

        if (pblock) { // ���ָ��������
            BOOST_FOREACH(const CTxIn& txin, tx.vin) { // �������������б�
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(txin.prevout);
                while (range.first != range.second) {
                    if (range.first->second != tx.GetHash()) {
                        LogPrintf("Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s:%i)\n", tx.GetHash().ToString(), pblock->GetHash().ToString(), range.first->second.ToString(), range.first->first.hash.ToString(), range.first->first.n);
                        MarkConflicted(pblock->GetHash(), range.first->second); // ��ǹ�ϣ��ͻ
                    }
                    range.first++;
                }
            }
        }

        bool fExisted = mapWallet.count(tx.GetHash()) != 0;
        if (fExisted && !fUpdate) return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx))
        {
            CWalletTx wtx(this,tx);

            // Get merkle branch if transaction was found in a block
            if (pblock)
                wtx.SetMerkleBranch(*pblock);

            // Do not flush the wallet here for performance reasons
            // this is safe, as in case of a crash, we rescan the necessary blocks on startup through our SetBestChain-mechanism
            CWalletDB walletdb(strWalletFile, "r+", false);

            return AddToWallet(wtx, false, &walletdb);
        }
    }
    return false;
}

bool CWallet::AbandonTransaction(const uint256& hashTx)
{
    LOCK2(cs_main, cs_wallet); // ����

    // Do not flush the wallet here for performance reasons
    CWalletDB walletdb(strWalletFile, "r+", false); // ��Ϊ����ԭ��Ҫ������ˢ��Ǯ��

    std::set<uint256> todo; // �����б�
    std::set<uint256> done; // ������б�

    // Can't mark abandoned if confirmed or in mempool // ����ȷ�ϻ����ڴ���еĽ������޷����������
    assert(mapWallet.count(hashTx)); // ��齻���Ƿ���Ǯ����
    CWalletTx& origtx = mapWallet[hashTx]; // ��ȡָ����Ǯ������
    if (origtx.GetDepthInMainChain() > 0 || origtx.InMempool()) { // ��������������ȴ��� 0 ���ý�������������ý������ڴ����
        return false;
    }

    todo.insert(hashTx); // ��������б�

    while (!todo.empty()) { // �����б�ǿ�
        uint256 now = *todo.begin(); // ȡ�������б�ĵ�һ��
        todo.erase(now);
        done.insert(now); // ����������б�
        assert(mapWallet.count(now));
        CWalletTx& wtx = mapWallet[now]; // ��ȡ��Ӧ��Ǯ������
        int currentconfirm = wtx.GetDepthInMainChain(); // ��ȡ�ý����������������ϵ������Ϊȷ����
        // If the orig tx was not in block, none of its spends can be
        assert(currentconfirm <= 0);
        // if (currentconfirm < 0) {Tx and spends are already conflicted, no need to abandon}
        if (currentconfirm == 0 && !wtx.isAbandoned()) { // ��ǰȷ��Ϊ 0 ��Ǯ������δ���������
            // If the orig tx was not in block/mempool, none of its spends can be in mempool // �������л��Ѷ������ڴ����
            assert(!wtx.InMempool()); // Ǯ�����ײ����ڴ����
            wtx.nIndex = -1;
            wtx.setAbandoned(); // ��Ǯ�����ױ��Ϊ������
            wtx.MarkDirty(); // ��Ǹý����ѱ䶯
            wtx.WriteToDisk(&walletdb); // д��Ǯ�����ݿ�
            NotifyTransactionChanged(this, wtx.GetHash(), CT_UPDATED);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them abandoned too // ���������е�����������Ǯ���еĽ���Ϊ������
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(hashTx, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now) { // �������׻���ӳ�䣬��ȫ��Ϊ�ý��׵����
                if (!done.count(iter->second)) { // ��Ӧ����������������б�
                    todo.insert(iter->second); // �Ѹý��׼�������б�
                }
                iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance // ������׸ı䡰��ͻ��״̬����ı���������ѵĿ�����
            // available of the outputs it spends. So force those to be recomputed // ����ǿ�����¼��㡣
            BOOST_FOREACH(const CTxIn& txin, wtx.vin)
            {
                if (mapWallet.count(txin.prevout.hash)) // ��ǰһ�ʽ��׵���Ǯ����
                    mapWallet[txin.prevout.hash].MarkDirty(); // �Ѹý���������Ӧ��Ǯ�����ױ��Ϊ�Ѹı�
            }
        }
    }

    return true;
}

void CWallet::MarkConflicted(const uint256& hashBlock, const uint256& hashTx)
{
    LOCK2(cs_main, cs_wallet);

    int conflictconfirms = 0;
    if (mapBlockIndex.count(hashBlock)) {
        CBlockIndex* pindex = mapBlockIndex[hashBlock];
        if (chainActive.Contains(pindex)) {
            conflictconfirms = -(chainActive.Height() - pindex->nHeight + 1);
        }
    }
    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (conflictconfirms >= 0)
        return;

    // Do not flush the wallet here for performance reasons
    CWalletDB walletdb(strWalletFile, "r+", false);

    std::set<uint256> todo;
    std::set<uint256> done;

    todo.insert(hashTx);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        assert(mapWallet.count(now));
        CWalletTx& wtx = mapWallet[now];
        int currentconfirm = wtx.GetDepthInMainChain();
        if (conflictconfirms < currentconfirm) {
            // Block is 'more conflicted' than current confirm; update.
            // Mark transaction as conflicted with this block.
            wtx.nIndex = -1;
            wtx.hashBlock = hashBlock;
            wtx.MarkDirty();
            wtx.WriteToDisk(&walletdb);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(now, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now) {
                 if (!done.count(iter->second)) {
                     todo.insert(iter->second);
                 }
                 iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            BOOST_FOREACH(const CTxIn& txin, wtx.vin)
            {
                if (mapWallet.count(txin.prevout.hash))
                    mapWallet[txin.prevout.hash].MarkDirty();
            }
        }
    }
}

void CWallet::SyncTransaction(const CTransaction& tx, const CBlock* pblock)
{
    LOCK2(cs_main, cs_wallet); // Ǯ������

    if (!AddToWalletIfInvolvingMe(tx, pblock, true)) // ��Ӹý��׵�Ǯ��
        return; // Not one of ours

    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also: // ������׸ı䡰�ѳ�ͻ��״̬���ı��仨������Ŀ���������ǿ�����¼��㣬�ң�
    BOOST_FOREACH(const CTxIn& txin, tx.vin) // �������������б�
    {
        if (mapWallet.count(txin.prevout.hash)) // ���ý��������ǰһ������Ľ�����Ǯ������ӳ���б���
            mapWallet[txin.prevout.hash].MarkDirty(); // ��Ǹý����Ѹı�
    }
}


isminetype CWallet::IsMine(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet); // Ǯ������
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash); // �ڱ���Ǯ���в�ѯǰһ�ʽ������
        if (mi != mapWallet.end()) // ���ҵ�
        {
            const CWalletTx& prev = (*mi).second; // ��ȡǮ������
            if (txin.prevout.n < prev.vout.size()) // ǰһ�ʽ����������ڷ�Χ֮��
                return IsMine(prev.vout[txin.prevout.n]); // ��֤ǰһ�ʽ�������Ƿ����ڱ���Ǯ��
        }
    }
    return ISMINE_NO; // 0 ��ʾǰһ�ʽ��ײ����ڱ���Ǯ��
}

CAmount CWallet::GetDebit(const CTxIn &txin, const isminefilter& filter) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]) & filter)
                    return prev.vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

isminetype CWallet::IsMine(const CTxOut& txout) const
{
    return ::IsMine(*this, txout.scriptPubKey); // ���ý����Ƿ�������
}

CAmount CWallet::GetCredit(const CTxOut& txout, const isminefilter& filter) const // 4
{
    if (!MoneyRange(txout.nValue)) // ���������Χ���
        throw std::runtime_error("CWallet::GetCredit(): value out of range");
    return ((IsMine(txout) & filter) ? txout.nValue : 0); // �� IsMine ���� 4���򷵻ؽ��������ֵ
}

bool CWallet::IsChange(const CTxOut& txout) const
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (::IsMine(*this, txout.scriptPubKey))
    {
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
            return true;

        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

CAmount CWallet::GetChange(const CTxOut& txout) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error("CWallet::GetChange(): value out of range");
    return (IsChange(txout) ? txout.nValue : 0);
}

bool CWallet::IsMine(const CTransaction& tx) const
{
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
        if (IsMine(txout))
            return true;
    return false;
}

bool CWallet::IsFromMe(const CTransaction& tx) const
{
    return (GetDebit(tx, ISMINE_ALL) > 0);
}

CAmount CWallet::GetDebit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nDebit = 0;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        nDebit += GetDebit(txin, filter);
        if (!MoneyRange(nDebit))
            throw std::runtime_error("CWallet::GetDebit(): value out of range");
    }
    return nDebit;
}

CAmount CWallet::GetCredit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nCredit = 0;
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        nCredit += GetCredit(txout, filter);
        if (!MoneyRange(nCredit))
            throw std::runtime_error("CWallet::GetCredit(): value out of range");
    }
    return nCredit;
}

CAmount CWallet::GetChange(const CTransaction& tx) const
{
    CAmount nChange = 0;
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        nChange += GetChange(txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error("CWallet::GetChange(): value out of range");
    }
    return nChange;
}

int64_t CWalletTx::GetTxTime() const
{
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase())
        {
            // Generated block
            if (!hashUnset())
            {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && !hashUnset())
                {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetAmounts(list<COutputEntry>& listReceived,
                           list<COutputEntry>& listSent, CAmount& nFee, string& strSentAccount, const isminefilter& filter) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    CAmount nDebit = GetDebit(filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    for (unsigned int i = 0; i < vout.size(); ++i)
    {
        const CTxOut& txout = vout[i];
        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
        }
        else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;

        if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable())
        {
            LogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                     this->GetHash().ToString());
            address = CNoDestination();
        }

        COutputEntry output = {address, txout.nValue, (int)i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output);
    }

}

void CWalletTx::GetAccountAmounts(const string& strAccount, CAmount& nReceived,
                                  CAmount& nSent, CAmount& nFee, const isminefilter& filter) const
{
    nReceived = nSent = nFee = 0;

    CAmount allFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;
    GetAmounts(listReceived, listSent, allFee, strSentAccount, filter);

    if (strAccount == strSentAccount)
    {
        BOOST_FOREACH(const COutputEntry& s, listSent)
            nSent += s.amount;
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        BOOST_FOREACH(const COutputEntry& r, listReceived)
        {
            if (pwallet->mapAddressBook.count(r.destination))
            {
                map<CTxDestination, CAddressBookData>::const_iterator mi = pwallet->mapAddressBook.find(r.destination);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second.name == strAccount)
                    nReceived += r.amount;
            }
            else if (strAccount.empty())
            {
                nReceived += r.amount;
            }
        }
    }
}


bool CWalletTx::WriteToDisk(CWalletDB *pwalletdb)
{
    return pwalletdb->WriteTx(GetHash(), *this);
}

/**
 * Scan the block chain (starting in pindexStart) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated.
 */ // ɨ������������ pindexStart ��ʼ���Ľ��ס���� fUpdate Ϊ true����Ǯ�����Ѵ��ڵ��ҵ��Ľ��׽���������
int CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
{
    int ret = 0; // ֻҪ������һ�ʣ���ֵ�ͻ� +1
    int64_t nNow = GetTime(); // ��ȡ��ǰʱ��
    const CChainParams& chainParams = Params(); // ��ȡ������

    CBlockIndex* pindex = pindexStart; // �õ���ʼ��������
    {
        LOCK2(cs_main, cs_wallet); // Ǯ������

        // no need to read and scan block, if block was created before // ����������ǵ�Ǯ������֮ǰ�����Ŀ飬
        // our wallet birthday (as adjusted for block time variability) // ����Ҫ��ȡ��ɨ��������Ϣ�����ݿ�ʱ��ɱ��Խ��е�����
        while (pindex && nTimeFirstKey && (pindex->GetBlockTime() < (nTimeFirstKey - 7200))) // ������ʱ����Ǯ������ǰ 2h
            pindex = chainActive.Next(pindex); // ����������

        ShowProgress(_("Rescanning..."), 0); // show rescan progress in GUI as dialog or on splashscreen, if -rescan on startup
        double dProgressStart = Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), pindex, false);
        double dProgressTip = Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), chainActive.Tip(), false);
        while (pindex) // �����������
        {
            if (pindex->nHeight % 100 == 0 && dProgressTip - dProgressStart > 0.0) // ɨ�����
                ShowProgress(_("Rescanning..."), std::max(1, std::min(99, (int)((Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), pindex, false) - dProgressStart) / (dProgressTip - dProgressStart) * 100))));

            CBlock block;
            ReadBlockFromDisk(block, pindex, Params().GetConsensus()); // �Ӵ����϶�ȡ������Ϣ
            BOOST_FOREACH(CTransaction& tx, block.vtx) // �������齻���б�
            {
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate)) // ����һ�ʽ���
                    ret++;
            }
            pindex = chainActive.Next(pindex); // ָ����һ��
            if (GetTime() >= nNow + 60) { // ʱ�������� 60s
                nNow = GetTime(); // ����ʱ��
                LogPrintf("Still rescanning. At block %d. Progress=%f\n", pindex->nHeight, Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), pindex));
            }
        }
        ShowProgress(_("Rescanning..."), 100); // hide progress dialog in GUI
    }
    return ret;
}

void CWallet::ReacceptWalletTransactions()
{
    // If transactions aren't being broadcasted, don't let them into local mempool either
    if (!fBroadcastTransactions) // �������δ���㲥��Ҳ�������ǽ��뱾�ؽ����ڴ��
        return;
    LOCK2(cs_main, cs_wallet); // Ǯ������
    std::map<int64_t, CWalletTx*> mapSorted; // λ����Ǯ������ӳ���б�

    // Sort pending wallet transactions based on their initial wallet insertion order // �������ǳ�ʼ��Ǯ������˳������������Ǯ������
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet) // ����Ǯ������ӳ���б�
    {
        const uint256& wtxid = item.first; // ��ȡ��������
        CWalletTx& wtx = item.second; // ��ȡǮ������
        assert(wtx.GetHash() == wtxid); // ��֤�������������Ƿ�һ��

        int nDepth = wtx.GetDepthInMainChain(); // ��ȡ�����������е����

        if (!wtx.IsCoinBase() && (nDepth == 0 && !wtx.isAbandoned())) { // �ý��ײ����� coinbase �� �ý������Ϊ 0����ʾ�ý��׻�δ�����ܣ��Ҹý���δ������
            mapSorted.insert(std::make_pair(wtx.nOrderPos, &wtx)); // ������ʱӳ���б�
        }
    }

    // Try to add wallet transactions to memory pool // �������Ǯ�����׵��ڴ��
    BOOST_FOREACH(PAIRTYPE(const int64_t, CWalletTx*)& item, mapSorted) // �������б�
    {
        CWalletTx& wtx = *(item.second); // ��ȡǮ������

        LOCK(mempool.cs); // �ڴ������
        wtx.AcceptToMemoryPool(false); // �ѽ��׷����ڴ��
    }
}

bool CWalletTx::RelayWalletTransaction()
{
    assert(pwallet->GetBroadcastTransactions()); // ��֤Ǯ���㲥�����Ƿ���
    if (!IsCoinBase()) // ���ý��׷Ǵ��ҽ���
    {
        if (GetDepthInMainChain() == 0 && !isAbandoned()) { // �������Ϊ 0����δ�������� δ�����Ϊ������
            LogPrintf("Relaying wtx %s\n", GetHash().ToString()); // ��¼�м̽��׹�ϣ
            RelayTransaction((CTransaction)*this); // ���н����м�
            return true;
        }
    }
    return false;
}

set<uint256> CWalletTx::GetConflicts() const
{
    set<uint256> result;
    if (pwallet != NULL)
    {
        uint256 myHash = GetHash();
        result = pwallet->GetConflicts(myHash);
        result.erase(myHash);
    }
    return result;
}

CAmount CWalletTx::GetDebit(const isminefilter& filter) const
{
    if (vin.empty())
        return 0;

    CAmount debit = 0;
    if(filter & ISMINE_SPENDABLE)
    {
        if (fDebitCached)
            debit += nDebitCached;
        else
        {
            nDebitCached = pwallet->GetDebit(*this, ISMINE_SPENDABLE);
            fDebitCached = true;
            debit += nDebitCached;
        }
    }
    if(filter & ISMINE_WATCH_ONLY)
    {
        if(fWatchDebitCached)
            debit += nWatchDebitCached;
        else
        {
            nWatchDebitCached = pwallet->GetDebit(*this, ISMINE_WATCH_ONLY);
            fWatchDebitCached = true;
            debit += nWatchDebitCached;
        }
    }
    return debit;
}

CAmount CWalletTx::GetCredit(const isminefilter& filter) const
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    int64_t credit = 0;
    if (filter & ISMINE_SPENDABLE)
    {
        // GetBalance can assume transactions in mapWallet won't change
        if (fCreditCached)
            credit += nCreditCached;
        else
        {
            nCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
            fCreditCached = true;
            credit += nCreditCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY)
    {
        if (fWatchCreditCached)
            credit += nWatchCreditCached;
        else
        {
            nWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
            fWatchCreditCached = true;
            credit += nWatchCreditCached;
        }
    }
    return credit;
}

CAmount CWalletTx::GetImmatureCredit(bool fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureCreditCached)
            return nImmatureCreditCached;
        nImmatureCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
        fImmatureCreditCached = true;
        return nImmatureCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableCredit(bool fUseCache) const
{
    if (pwallet == 0) // Ǯ��������
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0) // ��Ϊ���ҽ��ף�����Ҫ����
        return 0;

    if (fUseCache && fAvailableCreditCached) // ��ʹ�û��� �� �ѻ���
        return nAvailableCreditCached; // ֱ�ӷ��ػ�����

    CAmount nCredit = 0;
    uint256 hashTx = GetHash(); // ��ȡ�����׹�ϣ
    for (unsigned int i = 0; i < vout.size(); i++) // ������������б�
    {
        if (!pwallet->IsSpent(hashTx, i)) // ���ý������δ����
        {
            const CTxOut &txout = vout[i]; // ��ȡ�ý������
            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE); // �ۼӽ���������
            if (!MoneyRange(nCredit)) // ����Χ���
                throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
        }
    }

    nAvailableCreditCached = nCredit; // ���л���
    fAvailableCreditCached = true; // �����־
    return nCredit; // �������
}

CAmount CWalletTx::GetImmatureWatchOnlyCredit(const bool& fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureWatchCreditCached)
            return nImmatureWatchCreditCached;
        nImmatureWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
        fImmatureWatchCreditCached = true;
        return nImmatureWatchCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableWatchOnlyCredit(const bool& fUseCache) const
{
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableWatchCreditCached)
        return nAvailableWatchCreditCached;

    CAmount nCredit = 0;
    for (unsigned int i = 0; i < vout.size(); i++)
    {
        if (!pwallet->IsSpent(GetHash(), i))
        {
            const CTxOut &txout = vout[i];
            nCredit += pwallet->GetCredit(txout, ISMINE_WATCH_ONLY);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
        }
    }

    nAvailableWatchCreditCached = nCredit;
    fAvailableWatchCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetChange() const
{
    if (fChangeCached)
        return nChangeCached;
    nChangeCached = pwallet->GetChange(*this);
    fChangeCached = true;
    return nChangeCached;
}

bool CWalletTx::InMempool() const
{
    LOCK(mempool.cs);
    if (mempool.exists(GetHash())) { // ���ý��������Ƿ�������ڴ����
        return true; // ���� true
    }
    return false;
}

bool CWalletTx::IsTrusted() const
{
    // Quick answer in most cases
    if (!CheckFinalTx(*this))
        return false;
    int nDepth = GetDepthInMainChain();
    if (nDepth >= 1)
        return true;
    if (nDepth < 0)
        return false;
    if (!bSpendZeroConfChange || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
        return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    if (!InMempool())
        return false;

    // Trusted if all inputs are from us and are in the mempool:
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // Transactions not sent by us: not trusted
        const CWalletTx* parent = pwallet->GetWalletTx(txin.prevout.hash);
        if (parent == NULL)
            return false;
        const CTxOut& parentOut = parent->vout[txin.prevout.n];
        if (pwallet->IsMine(parentOut) != ISMINE_SPENDABLE)
            return false;
    }
    return true;
}

bool CWalletTx::IsEquivalentTo(const CWalletTx& tx) const
{
        CMutableTransaction tx1 = *this;
        CMutableTransaction tx2 = tx;
        for (unsigned int i = 0; i < tx1.vin.size(); i++) tx1.vin[i].scriptSig = CScript();
        for (unsigned int i = 0; i < tx2.vin.size(); i++) tx2.vin[i].scriptSig = CScript();
        return CTransaction(tx1) == CTransaction(tx2);
}

std::vector<uint256> CWallet::ResendWalletTransactionsBefore(int64_t nTime)
{
    std::vector<uint256> result; // ���������б�

    LOCK(cs_wallet); // Ǯ������
    // Sort them in chronological order // ��ʱ��˳������
    multimap<unsigned int, CWalletTx*> mapSorted; // �Ź���Ľ����б�
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet) // ����Ǯ������ӳ���б�
    {
        CWalletTx& wtx = item.second; // ��ȡǮ������
        // Don't rebroadcast if newer than nTime: // ָ��ʱ����Ľ��ײ��ٹ㲥
        if (wtx.nTimeReceived > nTime)
            continue;
        mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx)); // �����Ź���Ľ����б�
    }
    BOOST_FOREACH(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted) // �����ý����б�
    {
        CWalletTx& wtx = *item.second; // ��ȡ����
        if (wtx.RelayWalletTransaction()) // �м̸�Ǯ������
            result.push_back(wtx.GetHash()); // ��ȡ���׹�ϣ���뽻�������б�
    }
    return result; // ���ط��͵Ľ��������б�
}

void CWallet::ResendWalletTransactions(int64_t nBestBlockTime)
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions. // ��������������������������ǵĽ��ס�
    if (GetTime() < nNextResend || !fBroadcastTransactions)
        return;
    bool fFirst = (nNextResend == 0);
    nNextResend = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time // ����һ���������ִ������
    if (nBestBlockTime < nLastResend)
        return;
    nLastResend = GetTime();

    // Rebroadcast unconfirmed txes older than 5 minutes before the last
    // block was found: // ���ҵ����һ����ǰ�� 5 ����ǰ�㲥δȷ�ϵĽ��׼�
    std::vector<uint256> relayed = ResendWalletTransactionsBefore(nBestBlockTime-5*60);
    if (!relayed.empty()) // ���м����ݣ����ף��ǿգ���¼�ٹ㲥�Ľ�����
        LogPrintf("%s: rebroadcast %u unconfirmed transactions\n", __func__, relayed.size());
}

/** @} */ // end of mapWallet




/** @defgroup Actions
 *
 * @{
 */


CAmount CWallet::GetBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet); // Ǯ������
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        { // ����Ǯ��ӳ��
            const CWalletTx* pcoin = &(*it).second; // ��ȡǮ������
            if (pcoin->IsTrusted()) // �ý��׿��ţ���ȷ�ϣ�
                nTotal += pcoin->GetAvailableCredit(); // ��ȡ�������ۼ�
        }
    }

    return nTotal; // ���������
}

CAmount CWallet::GetUnconfirmedBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        { // ����Ǯ������ӳ���б�
            const CWalletTx* pcoin = &(*it).second; // ��ȡǮ������
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 && pcoin->InMempool()) // �ý��ײ����ţ�δȷ�ϣ� �� �������������Ϊ 0 �� �������ڴ���У�δ������
                nTotal += pcoin->GetAvailableCredit(); // ��ȡ�ۼӿ������
        }
    }
    return nTotal; // ���������
}

CAmount CWallet::GetImmatureBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }

    return nTotal;
}

CAmount CWallet::GetUnconfirmedWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 && pcoin->InMempool())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureWatchOnlyCredit();
        }
    }
    return nTotal;
}

void CWallet::AvailableCoins(vector<COutput>& vCoins, bool fOnlyConfirmed, const CCoinControl *coinControl, bool fIncludeZeroValue) const
{
    vCoins.clear(); // ����ձ�����б�

    {
        LOCK2(cs_main, cs_wallet); // Ǯ������
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        { // ����Ǯ������ӳ���б�
            const uint256& wtxid = it->first; // ��ȡǮ����������
            const CWalletTx* pcoin = &(*it).second; // ��ȡǮ������

            if (!CheckFinalTx(*pcoin)) // �����ս���
                continue; // ����

            if (fOnlyConfirmed && !pcoin->IsTrusted()) // ��������Ҫȷ�� �� ������
                continue; // ����

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0) // ������Ϊ���ҽ��� �� δ����
                continue; // ����

            int nDepth = pcoin->GetDepthInMainChain(); // ��ȡ�������
            if (nDepth < 0) // ���С�� 0 ��ʾδ����
                continue; // ����

            // We should not consider coins which aren't at least in our mempool // ���ǲ�Ӧ�ÿ��ǲ����ڴ�صĽ���
            // It's possible for these to be conflicted via ancestors which we may never be able to detect // ��Щ���ܻ�ͨ�������޷���⵽�����ȷ�����ͻ
            if (nDepth == 0 && !pcoin->InMempool()) // ����δ���� �� �����ڴ����
                continue; // ����

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) { // ������������б�
                isminetype mine = IsMine(pcoin->vout[i]); // �жϸ�����Ƿ������Լ�
                if (!(IsSpent(wtxid, i)) && mine != ISMINE_NO && // ���δ���� �� �����Լ� ��
                    !IsLockedCoin((*it).first, i) && (pcoin->vout[i].nValue > 0 || fIncludeZeroValue) && // ���������ı� �� ����������� 0 �� ���� 0 ֵ��־Ϊ true�� ��
                    (!coinControl || !coinControl->HasSelected() || coinControl->fAllowOtherInputs || coinControl->IsSelected((*it).first, i)))
                        vCoins.push_back(COutput(pcoin, i, nDepth,
                                                 ((mine & ISMINE_SPENDABLE) != ISMINE_NO) ||
                                                  (coinControl && coinControl->fAllowWatchOnly && (mine & ISMINE_WATCH_SOLVABLE) != ISMINE_NO))); // ���������б�
            }
        }
    }
}

static void ApproximateBestSubset(vector<pair<CAmount, pair<const CWalletTx*,unsigned int> > >vValue, const CAmount& nTotalLower, const CAmount& nTargetValue,
                                  vector<char>& vfBest, CAmount& nBest, int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    seed_insecure_rand();

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        CAmount nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng is fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                if (nPass == 0 ? insecure_rand()&1 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }

    //Reduces the approximate best subset by removing any inputs that are smaller than the surplus of nTotal beyond nTargetValue. 
    for (unsigned int i = 0; i < vValue.size(); i++)
    {                        
        if (vfBest[i] && (nBest - vValue[i].first) >= nTargetValue )
        {
            vfBest[i] = false;
            nBest -= vValue[i].first;
        }
    }
}

bool CWallet::SelectCoinsMinConf(const CAmount& nTargetValue, int nConfMine, int nConfTheirs, vector<COutput> vCoins,
                                 set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    pair<CAmount, pair<const CWalletTx*,unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<CAmount>::max();
    coinLowestLarger.second.first = NULL;
    vector<pair<CAmount, pair<const CWalletTx*,unsigned int> > > vValue;
    CAmount nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    BOOST_FOREACH(const COutput &output, vCoins)
    {
        if (!output.fSpendable)
            continue;

        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? nConfMine : nConfTheirs))
            continue;

        int i = output.i;
        CAmount n = pcoin->vout[i].nValue;

        pair<CAmount,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

        if (n == nTargetValue)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            return true;
        }
        else if (n < nTargetValue + MIN_CHANGE)
        {
            vValue.push_back(coin);
            nTotalLower += n;
        }
        else if (n < coinLowestLarger.first)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    vector<char> vfBest;
    CAmount nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + MIN_CHANGE)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + MIN_CHANGE, vfBest, nBest);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + MIN_CHANGE) || coinLowestLarger.first <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    }
    else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

        LogPrint("selectcoins", "SelectCoins() best subset: ");
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                LogPrint("selectcoins", "%s ", FormatMoney(vValue[i].first));
        LogPrint("selectcoins", "total %s\n", FormatMoney(nBest));
    }

    return true;
}

bool CWallet::SelectCoins(const CAmount& nTargetValue, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet, const CCoinControl* coinControl) const
{
    vector<COutput> vCoins; // ������б�
    AvailableCoins(vCoins, true, coinControl); // ��ȡ���õıҵ�����б�

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure) // ����ȫ��ѡ�������������ϣ������ѡ�еĶ����뽻�ף�
    if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs)
    {
        BOOST_FOREACH(const COutput& out, vCoins) // ��������б�
        {
            if (!out.fSpendable) // ����������ɻ���
                 continue; // ����
            nValueRet += out.tx->vout[out.i].nValue; // �ۼ�������������ֵ
            setCoinsRet.insert(make_pair(out.tx, out.i)); // �ѽ��׺������������Ҽ���
        }
        return (nValueRet >= nTargetValue); // ���ܺͱ�Ŀ��ֵ�󣬷��� true
    }

    // calculate value from preset inputs and store them // ����Ԥ�������ֵ���洢����
    set<pair<const CWalletTx*, uint32_t> > setPresetCoins; // Ԥ��Ҽ���
    CAmount nValueFromPresetInputs = 0; // ����Ԥ�������ֵ

    std::vector<COutPoint> vPresetInputs; // Ԥ�������б�
    if (coinControl)
        coinControl->ListSelected(vPresetInputs);
    BOOST_FOREACH(const COutPoint& outpoint, vPresetInputs)
    {
        map<uint256, CWalletTx>::const_iterator it = mapWallet.find(outpoint.hash);
        if (it != mapWallet.end())
        {
            const CWalletTx* pcoin = &it->second;
            // Clearly invalid input, fail
            if (pcoin->vout.size() <= outpoint.n)
                return false;
            nValueFromPresetInputs += pcoin->vout[outpoint.n].nValue;
            setPresetCoins.insert(make_pair(pcoin, outpoint.n));
        } else
            return false; // TODO: Allow non-wallet inputs
    }

    // remove preset inputs from vCoins
    for (vector<COutput>::iterator it = vCoins.begin(); it != vCoins.end() && coinControl && coinControl->HasSelected();)
    {
        if (setPresetCoins.count(make_pair(it->tx, it->i)))
            it = vCoins.erase(it);
        else
            ++it;
    }

    bool res = nTargetValue <= nValueFromPresetInputs ||
        SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 6, vCoins, setCoinsRet, nValueRet) ||
        SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 1, vCoins, setCoinsRet, nValueRet) ||
        (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, vCoins, setCoinsRet, nValueRet));

    // because SelectCoinsMinConf clears the setCoinsRet, we now add the possible inputs to the coinset
    setCoinsRet.insert(setPresetCoins.begin(), setPresetCoins.end());

    // add preset inputs to the total value selected
    nValueRet += nValueFromPresetInputs;

    return res;
}

bool CWallet::FundTransaction(CMutableTransaction& tx, CAmount &nFeeRet, int& nChangePosRet, std::string& strFailReason, bool includeWatching)
{
    vector<CRecipient> vecSend; // 1.�����б�

    // Turn the txout set into a CRecipient vector // �ѽ��������ת��Ϊ���ͣ������ߣ��б�
    BOOST_FOREACH(const CTxOut& txOut, tx.vout) // ������������б�
    {
        CRecipient recipient = {txOut.scriptPubKey, txOut.nValue, false}; // ��ʼ�������߶���
        vecSend.push_back(recipient); // ���뷢���б�
    }

    CCoinControl coinControl;
    coinControl.fAllowOtherInputs = true;
    coinControl.fAllowWatchOnly = includeWatching;
    BOOST_FOREACH(const CTxIn& txin, tx.vin) // 2.�������������б�
        coinControl.Select(txin.prevout); // �������ǰһ�ʽ�����������ѡ�񼯺�

    CReserveKey reservekey(this);
    CWalletTx wtx; // ����һ��Ǯ������
    if (!CreateTransaction(vecSend, wtx, reservekey, nFeeRet, nChangePosRet, strFailReason, &coinControl, false)) // 3.��������
        return false;

    if (nChangePosRet != -1) // 4.���������λ�ã���ţ������� -1����ʾ��λ��
        tx.vout.insert(tx.vout.begin() + nChangePosRet, wtx.vout[nChangePosRet]); // ����ԭ��������б��ָ��λ��

    // Add new txins (keeping original txin scriptSig/order) // 5.����µĽ��������б�����ԭʼ��������ű�ǩ��/˳��
    BOOST_FOREACH(const CTxIn& txin, wtx.vin) // �����µ�Ǯ�����������б�
    {
        bool found = false;
        BOOST_FOREACH(const CTxIn& origTxIn, tx.vin) // �����ɵĽ��������б�
        {
            if (txin.prevout.hash == origTxIn.prevout.hash && txin.prevout.n == origTxIn.prevout.n) // �����ظ����루��ͬ����һ�ʽ��׹�ϣ�������ţ�
            {
                found = true;
                break;
            }
        }
        if (!found) // ��δ�ҵ�������
            tx.vin.push_back(txin); // �Ѹ��������ԭ���׵������б�
    }

    return true; // �ɹ����� true
}

bool CWallet::CreateTransaction(const vector<CRecipient>& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet,
                                int& nChangePosRet, std::string& strFailReason, const CCoinControl* coinControl, bool sign)
{
    CAmount nValue = 0; // 1.��¼���͵��ܽ��
    unsigned int nSubtractFeeFromAmount = 0; // �ӷ��ͽ���ȥ���ܽ��׷�
    BOOST_FOREACH (const CRecipient& recipient, vecSend) // ���������б�
    {
        if (nValue < 0 || recipient.nAmount < 0) // ���ͽ��Ϊ����
        {
            strFailReason = _("Transaction amounts must be positive"); // ��������ʧ��
            return false;
        }
        nValue += recipient.nAmount; // �ۼӷ��ͽ��

        if (recipient.fSubtractFeeFromAmount) // ���ӽ���м�ȥ���׷�
            nSubtractFeeFromAmount++; // ��ȥ���׷��ۼ�
    }
    if (vecSend.empty() || nValue < 0) // �����б�Ϊ�� �� ���͵��ܽ��Ϊ����
    {
        strFailReason = _("Transaction amounts must be positive"); // ��������ʧ��
        return false;
    }

    wtxNew.fTimeReceivedIsTxTime = true; // ����ʱ���ǽ���ʱ���־��Ϊ true
    wtxNew.BindWallet(this); // ���װ󶨵�ǰǮ��
    CMutableTransaction txNew; // �ױ�Ľ��׶���

    // Discourage fee sniping. // ��ֹ���׷��á�
    //
    // For a large miner the value of the transactions in the best block and
    // the mempool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    txNew.nLockTime = chainActive.Height(); // ��ȡ��������߶���Ϊ�ý��׵�����ʱ��

    // Secondly occasionally randomly pick a nLockTime even further back, so
    // that transactions that are delayed after signing for whatever reason,
    // e.g. high-latency mix networks and some CoinJoin implementations, have
    // better privacy. // ���ż�������ѡ��һ������ʱ�䣬�����κ�ԭ����ǩ�����ӳٵĽ��ס�
    if (GetRandInt(10) == 0) // �������Ϊ 0
        txNew.nLockTime = std::max(0, (int)txNew.nLockTime - GetRandInt(100)); // ʹ��һ��������ʱ����Ϊ����ʱ��

    assert(txNew.nLockTime <= (unsigned int)chainActive.Height()); // ����ʱ�����С�ڵ��ڵ�ǰ��������߶�
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD); // ����ʱ�����С������ֵ

    {
        LOCK2(cs_main, cs_wallet); // Ǯ������
        {
            nFeeRet = 0;
            // Start with no fee and loop until there is enough fee // ��ʼʱû�н��׷ѣ�ѭ��ֱ�����㹻�Ľ��׷�
            while (true)
            {
                txNew.vin.clear(); // ��ս��������б�
                txNew.vout.clear(); // ��ս�������б�
                wtxNew.fFromMe = true; // ���Ϊ�Լ������Ľ���
                nChangePosRet = -1;
                bool fFirst = true; // ��һ��ѭ����־

                CAmount nValueToSelect = nValue; // Ҫ���͵��ܽ��
                if (nSubtractFeeFromAmount == 0) // ������Ҫ�ӽ���м�ȥ���׷�
                    nValueToSelect += nFeeRet; // ���͵Ľ����Ͻ��׷�
                double dPriority = 0; // ���ȼ�
                // vouts to the payees // ������տ���
                BOOST_FOREACH (const CRecipient& recipient, vecSend) // 3.���������б�
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey); // ���콻���������

                    if (recipient.fSubtractFeeFromAmount) // ���ӽ���м�ȥ���׷�
                    {
                        txout.nValue -= nFeeRet / nSubtractFeeFromAmount; // Subtract fee equally from each selected recipient // ��ȥƽ��Ҫ��ȥ�Ľ��׷ѣ����ʽ��� / �ܹ�Ҫ��ȥ�Ľ��׷ѣ�

                        if (fFirst) // first receiver pays the remainder not divisible by output count
                        { // ���ǵ�һ��ѭ��
                            fFirst = false; // �״�ѭ����־��Ϊ false
                            txout.nValue -= nFeeRet % nSubtractFeeFromAmount; // �������ټ�ȥ������Ĳ���
                        }
                    }

                    if (txout.IsDust(::minRelayTxFee)) // ������С�м̽��׷��жϸý����Ƿ�Ϊ�۳�����
                    {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0) // �����ȥ���׷� �� ���׷Ѵ��� 0
                        {
                            if (txout.nValue < 0) // ����������Ľ��Ϊ����
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                        }
                        else
                            strFailReason = _("Transaction amount too small");
                        return false; // ��������ʧ��
                    } // �Ƿ۳�����
                    txNew.vout.push_back(txout); // ���뽻������б�
                }

                // Choose coins to use // 4.ѡ��Ҫʹ�õı�
                set<pair<const CWalletTx*,unsigned int> > setCoins; // Ӳ�Ҽ���
                CAmount nValueIn = 0; // ��¼ѡ���Ӳ���ܽ��
                if (!SelectCoins(nValueToSelect, setCoins, nValueIn, coinControl)) // ѡ��Ӳ��
                {
                    strFailReason = _("Insufficient funds");
                    return false; // ��������ʧ��
                }
                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins) // 5.����Ӳ�Ҽ���
                {
                    CAmount nCredit = pcoin.first->vout[pcoin.second].nValue; // ��ȡǮ������������
                    //The coin age after the next block (depth+1) is used instead of the current, // ʹ����һ���飨���+1��֮��ı�����浱ǰ��
                    //reflecting an assumption the user would accept a bit more delay for
                    //a chance at a free transaction. // ��Ӧ���û�������ѽ����и����ӳ��Ի�û���ļ��衣
                    //But mempool inputs might still be in the mempool, so their age stays 0 // ���ڴ�����������Ȼ���ڴ���У��������ǵı���Ϊ 0
                    int age = pcoin.first->GetDepthInMainChain(); // ��ȡ���������Ϊ����
                    assert(age >= 0); // ������
                    if (age != 0)
                        age += 1;
                    dPriority += (double)nCredit * age; // ����ͱ��������ڼ������ȼ�
                }

                const CAmount nChange = nValueIn - nValueToSelect; // 6.����
                if (nChange > 0) // ���� 0 ��ʾ��������
                {
                    // Fill a vout to ourself // ���һ������б������Լ�
                    // TODO: pass in scriptChange instead of reservekey so // TODO����������ű����� reservekey
                    // change transaction isn't always pay-to-bitcoin-address // �������㽻�ײ����� P2PKH
                    CScript scriptChange; // ����һ������ű�

                    // coin control: send change to custom address // �ҿ��ƣ��������㵽ָ����ַ
                    if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
                        scriptChange = GetScriptForDestination(coinControl->destChange); // �������ַ��ȡ����ű�

                    // no coin control: send change to newly generated address
                    else // �Ǳҿ��ƣ��������㵽�����ɵĵ�ַ
                    {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool // ����Կ����һ����Կ��
                        CPubKey vchPubKey;
                        bool ret;
                        ret = reservekey.GetReservedKey(vchPubKey); // ����Կ�ػ�ȡһ����Կ
                        assert(ret); // should never fail, as we just unlocked // Ӧ�ò���ʧ�ܣ���Ϊ���Ǹս���

                        scriptChange = GetScriptForDestination(vchPubKey.GetID()); // ���ݹ�Կ������ȡ����ű�
                    }

                    CTxOut newTxOut(nChange, scriptChange); // ͨ��������ͽű�����һ���µĽ������

                    // We do not move dust-change to fees, because the sender would end up paying more than requested. // ���ǲ���ѷ۳�����ת�����׷ѣ���Ϊ���������ջ�֧����������ķ��á�
                    // This would be against the purpose of the all-inclusive feature. // �⽫Υ������ȫ�����ܵ�Ŀ�ġ�
                    // So instead we raise the change and deduct from the recipient. // ��������������㲢���ٽ����߽�
                    if (nSubtractFeeFromAmount > 0 && newTxOut.IsDust(::minRelayTxFee)) // �ӽ���м�ȥ�Ľ��׷Ѵ��� 0 �� �½�������Ƿ۳����ף�ͨ����С�м̽��׷��жϣ�
                    {
                        CAmount nDust = newTxOut.GetDustThreshold(::minRelayTxFee) - newTxOut.nValue; // ����۳����
                        newTxOut.nValue += nDust; // raise change until no more dust // ��������ֱ��û�з۳�
                        for (unsigned int i = 0; i < vecSend.size(); i++) // subtract from first recipient // �ӵ�һ���������м�ȥ
                        { // ���������б�
                            if (vecSend[i].fSubtractFeeFromAmount)
                            {
                                txNew.vout[i].nValue -= nDust; // ��ȥ�۳�
                                if (txNew.vout[i].IsDust(::minRelayTxFee)) // ����������Ƿ۳�
                                {
                                    strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                                    return false; // ��������ʧ��
                                }
                                break; // ֻ�ı��һ������������
                            }
                        }
                    }

                    // Never create dust outputs; if we would, just
                    // add the dust to the fee. // �Ӳ������۳��������������룬ֻ��ӷ۳������׷�
                    if (newTxOut.IsDust(::minRelayTxFee)) // �µĽ�������Ƿ۳�
                    {
                        nFeeRet += nChange; // �������㵽���׷�
                        reservekey.ReturnKey(); // �������ַ��Ӧ��Կ�Ż���Կ��
                    }
                    else
                    { // ������Ƿ۳�
                        // Insert change txn at random position:
                        nChangePosRet = GetRandInt(txNew.vout.size()+1); // ��ȡһ�����λ��
                        vector<CTxOut>::iterator position = txNew.vout.begin()+nChangePosRet;
                        txNew.vout.insert(position, newTxOut); // �������㽻�׵���������б�����λ��
                    }
                } // ���򲻴�������
                else
                    reservekey.ReturnKey(); // ����Կ�Ż���Կ��

                // Fill vin // 7.��������б�
                //
                // Note how the sequence number is set to max()-1 so that the
                // nLockTime set above actually works. // ע�����������õ� max()-1 �����������õ�����ʱ��ʵ�ʹ�����
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) // �����Ҽ���
                    txNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second,CScript(), // ���뽻�������б�
                                              std::numeric_limits<unsigned int>::max()-1));

                // Sign // 8.ǩ��
                int nIn = 0; // ��������
                CTransaction txNewConst(txNew); // ͨ���ױ�Ľ��׹���һ�ʲ���Ľ���
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) // �����Ҽ���
                {
                    bool signSuccess; // ǩ��״̬
                    const CScript& scriptPubKey = coin.first->vout[coin.second].scriptPubKey; // ��ȡ�ű���Կ
                    CScript& scriptSigRes = txNew.vin[nIn].scriptSig; // ��ȡ�ű�ǩ��������
                    if (sign) // true ����ǩ��
                        signSuccess = ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, SIGHASH_ALL), scriptPubKey, scriptSigRes); // ����ǩ��
                    else
                        signSuccess = ProduceSignature(DummySignatureCreator(this), scriptPubKey, scriptSigRes);

                    if (!signSuccess) // ǩ��ʧ��
                    {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    }
                    nIn++; // ����������ż� 1
                }

                unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION); // ��ȡ���л����׵��ֽ���

                // Remove scriptSigs if we used dummy signatures for fee calculation
                if (!sign) { // �������ʹ������ǩ�����мƷѣ����Ƴ��ű�ǩ��
                    BOOST_FOREACH (CTxIn& vin, txNew.vin) // �������������б�
                        vin.scriptSig = CScript(); // �����սű�
                }

                // Embed the constructed transaction data in wtxNew. // 9.�ѹ���Ľ���Ƕ�뵽 txNew
                *static_cast<CTransaction*>(&wtxNew) = CTransaction(txNew);

                // Limit size // ���ƽ��״�С
                if (nBytes >= MAX_STANDARD_TX_SIZE) // ���л��Ľ��״�С����С�ڽ��״�С����
                {
                    strFailReason = _("Transaction too large");
                    return false; // ��������ʧ��
                }

                dPriority = wtxNew.ComputePriority(dPriority, nBytes); // ���㽻�����ȼ�

                // Can we complete this as a free transaction? // ���ǿ��԰�����Ϊ��ѽ����������
                if (fSendFreeTransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE) // ����ѷ��� �� ���״�СС�ڵ�����ѽ�����ֵ
                {
                    // Not enough fee: enough priority? // û���㹻�Ľ��׷ѣ��㹻�����ȼ���
                    double dPriorityNeeded = mempool.estimateSmartPriority(nTxConfirmTarget); // ���ܹ������ȼ�
                    // Require at least hard-coded AllowFree. // ������ҪӲ��� AllowFree
                    if (dPriority >= dPriorityNeeded && AllowFree(dPriority))
                        break;
                }

                CAmount nFeeNeeded = GetMinimumFee(nBytes, nTxConfirmTarget, mempool); // ��ȡ������С���׷�
                if (coinControl && nFeeNeeded > 0 && coinControl->nMinimumTotalFee > nFeeNeeded) {
                    nFeeNeeded = coinControl->nMinimumTotalFee;
                }

                // If we made it here and we aren't even able to meet the relay fee on the next pass, give up // ���������������������޷������´ε��м̽��׷ѣ�����
                // because we must be at the maximum allowed fee. // ��Ϊ���Ǳ���ﵽ����������ã���С�м̷ѣ���
                if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes)) // �����轻�׷�С����С�м̽��׷�
                {
                    strFailReason = _("Transaction too large for fee policy");
                    return false; // ��������ʧ��
                }

                if (nFeeRet >= nFeeNeeded) // ��ǰ���׷ѵ������轻�׷�ʱ
                    break; // Done, enough fee included. // ��ɣ�����

                // Include more fee and try again.
                nFeeRet = nFeeNeeded; // ���ý��׷�
                continue; // while
            }
        }
    }

    return true; // �����ɹ������� true
}

/**
 * Call after CreateTransaction unless you want to abort
 */ // ��������Ҫ�������� CreateTransaction ֮�����
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey)
{
    {
        LOCK2(cs_main, cs_wallet); // 1.Ǯ������
        LogPrintf("CommitTransaction:\n%s", wtxNew.ToString()); // ��¼������Ϣ
        {
            // This is only to keep the database open to defeat the auto-flush for the // ��ֻ��Ϊ���ڸ��ڼ��ڱ������ݿ���Է��Զ�ˢ�¡�
            // duration of this scope.  This is the only place where this optimization // ����Ψһ�����Ż�����������ĵط���
            // maybe makes sense; please don't do it anywhere else. // �벻Ҫ�������ط��������
            CWalletDB* pwalletdb = fFileBacked ? new CWalletDB(strWalletFile,"r+") : NULL; // ����Ǯ�����ݿ����r+ ��ʾ�ɶ�д��ʽ��Ǯ�����ݿ��ļ�

            // Take key pair from key pool so it won't be used again // ����Կ�����ó���Կ�ԣ��������޷��ٴα�ʹ��
            reservekey.KeepKey(); // ����Կ�����Ƴ�����Կ

            // Add tx to wallet, because if it has change it's also ours, // ��ӽ��׵�Ǯ������Ϊ�����������Ҳ�����ǵģ�
            // otherwise just for transaction history. // ��������ڽ��׽�����ʷ��¼��
            AddToWallet(wtxNew, false, pwalletdb); // ���Ǯ�����׵�Ǯ�����ݿ�

            // Notify that old coins are spent // ֪ͨ�ɵıұ�����
            set<CWalletTx*> setCoins; // Ǯ��������������
            BOOST_FOREACH(const CTxIn& txin, wtxNew.vin) // �����½��׵������б�
            {
                CWalletTx &coin = mapWallet[txin.prevout.hash]; // ��ȡ�������һ�������Ӧ��Ǯ������
                coin.BindWallet(this); // ��Ǯ���������Ǯ���ѱ䶯
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED); // ֪ͨǮ�����׸ı䣨���£�
            }

            if (fFileBacked) // ��Ǯ���ļ��ѱ���
                delete pwalletdb; // ����Ǯ�����ݿ����
        }

        // Track how many getdata requests our transaction gets // 2.׷�����ǵĽ��׻�ȡ�˶��ٴ� getdata ����
        mapRequestCount[wtxNew.GetHash()] = 0; // ��ʼ��Ϊ 0 ��

        if (fBroadcastTransactions) // �������˽��׹㲥��־
        {
            // Broadcast // �㲥
            if (!wtxNew.AcceptToMemoryPool(false)) // 3.�ѽ�����ӵ��ڴ����
            { // �ⲽ����ʧ�ܡ��ý����Ѿ�ǩ�𲢼�¼��
                // This must not fail. The transaction has already been signed and recorded.
                LogPrintf("CommitTransaction(): Error: Transaction not valid\n");
                return false;
            }
            wtxNew.RelayWalletTransaction(); // 4.�м�Ǯ������
        }
    }
    return true;
}

bool CWallet::AddAccountingEntry(const CAccountingEntry& acentry, CWalletDB & pwalletdb)
{
    if (!pwalletdb.WriteAccountingEntry_Backend(acentry)) // д���˻���Ŀĩ��
        return false;

    laccentries.push_back(acentry); // �����˻���Ŀ�б�
    CAccountingEntry & entry = laccentries.back(); // ��ȡ�б��е����һ�����ã���Ŀ
    wtxOrdered.insert(make_pair(entry.nOrderPos, TxPair((CWalletTx*)0, &entry))); // ����������ӳ���б�

    return true;
}

CAmount CWallet::GetRequiredFee(unsigned int nTxBytes)
{
    return std::max(minTxFee.GetFee(nTxBytes), ::minRelayTxFee.GetFee(nTxBytes));
}

CAmount CWallet::GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool)
{
    // payTxFee is user-set "I want to pay this much"
    CAmount nFeeNeeded = payTxFee.GetFee(nTxBytes);
    // User didn't set: use -txconfirmtarget to estimate...
    if (nFeeNeeded == 0) {
        int estimateFoundTarget = nConfirmTarget;
        nFeeNeeded = pool.estimateSmartFee(nConfirmTarget, &estimateFoundTarget).GetFee(nTxBytes);
        // ... unless we don't have enough mempool data for estimatefee, then use fallbackFee
        if (nFeeNeeded == 0)
            nFeeNeeded = fallbackFee.GetFee(nTxBytes);
    }
    // prevent user from paying a fee below minRelayTxFee or minTxFee
    nFeeNeeded = std::max(nFeeNeeded, GetRequiredFee(nTxBytes));
    // But always obey the maximum
    if (nFeeNeeded > maxTxFee)
        nFeeNeeded = maxTxFee;
    return nFeeNeeded;
}




DBErrors CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked) // �����״�����
        return DB_LOAD_OK; // ���� 0����ʾ�������
    fFirstRunRet = false; // �״����У��Ѹñ�־��Ϊ false
    DBErrors nLoadWalletRet = CWalletDB(strWalletFile,"cr+").LoadWallet(this); // ��Ǯ���ļ��м���Ǯ�����ڴ�
    if (nLoadWalletRet == DB_NEED_REWRITE) // 5 ��Ҫ��д
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet); // ��Ǯ������
            setKeyPool.clear(); // ���Կ�׳�
            // Note: can't top-up keypool here, because wallet is locked. // ע�������������ֵԿ�׳أ���ΪǮ�������ˡ�
            // User will be prompted to unlock wallet the next operation // �û�������ʾ��һ��������Ҫһ������Կ������Ǯ����
            // that requires a new key.
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK) // �����ش���
        return nLoadWalletRet; // ֱ�ӷ��ؼ���״̬
    fFirstRunRet = !vchDefaultKey.IsValid(); // ������֤Ĭ�Ϲ�Կ�Ƿ���Ч������Ч�����õ�һ������״̬Ϊ false

    uiInterface.LoadWallet(this); // UI ����������Ǯ��

    return DB_LOAD_OK; // 0
}


DBErrors CWallet::ZapWalletTx(std::vector<CWalletTx>& vWtx)
{
    if (!fFileBacked) // ��Ǯ��δ����
        return DB_LOAD_OK; // ���� 0
    DBErrors nZapWalletTxRet = CWalletDB(strWalletFile,"cr+").ZapWalletTx(this, vWtx); // ��Ǯ�����ݿ�
    if (nZapWalletTxRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool")) // ��дǮ�����ݿ��ļ�
        {
            LOCK(cs_wallet); // Ǯ������
            setKeyPool.clear(); // ��Կ�ؼ������
            // Note: can't top-up keypool here, because wallet is locked. // ע�����ﲻ�������Կ�أ���ΪǮ��������
            // User will be prompted to unlock wallet the next operation // ����Ҫ����Կ����һ������ʱ����Ǯ����
            // that requires a new key. // ϵͳ����ʾ�û���
        }
    }

    if (nZapWalletTxRet != DB_LOAD_OK)
        return nZapWalletTxRet;

    return DB_LOAD_OK;
}


bool CWallet::SetAddressBook(const CTxDestination& address, const string& strName, const string& strPurpose)
{
    bool fUpdated = false; // ���Ǯ����ַ���Ƿ���£�ָ��ַ�Ѵ��ڸ�������;��������ַ����
    {
        LOCK(cs_wallet); // mapAddressBook
        std::map<CTxDestination, CAddressBookData>::iterator mi = mapAddressBook.find(address); // �����ڵ�ַ���в��Ҹõ�ַ
        fUpdated = mi != mapAddressBook.end(); // ���ҵ��Ļ���������־��Ϊ true
        mapAddressBook[address].name = strName; // �˻���������ַ�Ѵ��ڣ�ֱ�Ӹı��˻������������õ�ַ
        if (!strPurpose.empty()) /* update purpose only if requested */ // ��;�ǿ�
            mapAddressBook[address].purpose = strPurpose; // �������Ѵ��ڵ�ַ����;
    }
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address) != ISMINE_NO,
                             strPurpose, (fUpdated ? CT_UPDATED : CT_NEW) ); // ֪ͨ��ַ���Ѹı�
    if (!fFileBacked) // �ļ�δ����
        return false;
    if (!strPurpose.empty() && !CWalletDB(strWalletFile).WritePurpose(CBitcoinAddress(address).ToString(), strPurpose)) // ��;�ǿ�ʱ��д��Ǯ�����ݿ�õ�ַ��Ӧ����;
        return false;
    return CWalletDB(strWalletFile).WriteName(CBitcoinAddress(address).ToString(), strName); // ���д���ַ��Ӧ���˻�����Ǯ�����ݿ�
}

bool CWallet::DelAddressBook(const CTxDestination& address)
{
    {
        LOCK(cs_wallet); // mapAddressBook

        if(fFileBacked)
        {
            // Delete destdata tuples associated with address
            std::string strAddress = CBitcoinAddress(address).ToString();
            BOOST_FOREACH(const PAIRTYPE(string, string) &item, mapAddressBook[address].destdata)
            {
                CWalletDB(strWalletFile).EraseDestData(strAddress, item.first);
            }
        }
        mapAddressBook.erase(address);
    }

    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address) != ISMINE_NO, "", CT_DELETED);

    if (!fFileBacked)
        return false;
    CWalletDB(strWalletFile).ErasePurpose(CBitcoinAddress(address).ToString());
    return CWalletDB(strWalletFile).EraseName(CBitcoinAddress(address).ToString());
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey)) // ��Ĭ�Ϲ�Կд��Ǯ�����ݿ� wallet.dat ��
            return false;
    }
    vchDefaultKey = vchPubKey; // ���øù�ԿΪĬ�Ϲ�Կ
    return true;
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys 
 */ // ��Ǿ���Կ����ԿΪ��ʹ�ã�������ȫ��������Կ
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet); // Ǯ������
        CWalletDB walletdb(strWalletFile); // ����Ǯ�����ݿ����
        BOOST_FOREACH(int64_t nIndex, setKeyPool) // ������Կ����������
            walletdb.ErasePool(nIndex); // ���������������ݿ��е���Կ
        setKeyPool.clear(); // �����Կ����������

        if (IsLocked()) // ���Ǯ���Ƿ����
            return false;

        int64_t nKeys = max(GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t)0); // ��ȡ��Կ�ش�С
        for (int i = 0; i < nKeys; i++)
        {
            int64_t nIndex = i+1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey())); // ��������Կ��������һ��д��Ǯ�����ݿ�
            setKeyPool.insert(nIndex); // ������Կ����������
        }
        LogPrintf("CWallet::NewKeyPool wrote %d new keys\n", nKeys); // ��¼д������Կ�ĸ���
    }
    return true;
}

bool CWallet::TopUpKeyPool(unsigned int kpSize)
{
    {
        LOCK(cs_wallet);

        if (IsLocked()) // �ٴμ��Ǯ���Ƿ���
            return false;

        CWalletDB walletdb(strWalletFile); // ͨ��Ǯ���ļ�������Ǯ�����ݿ����

        // Top up key pool // �������Կ��
        unsigned int nTargetSize;
        if (kpSize > 0) // ����� kpSize Ĭ��Ϊ 0
            nTargetSize = kpSize;
        else // ����������
            nTargetSize = max(GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t) 0); // Կ�׳ش�С��Ĭ�� 100

        while (setKeyPool.size() < (nTargetSize + 1)) // ������Կ�����Կ��ʵ��������� nTargetSize + 1 ����Կ��Ĭ��Ϊ 100 + 1 �� 101 ��
        {
            int64_t nEnd = 1;
            if (!setKeyPool.empty()) // ����Կ����Ϊ�գ��������Ϊ 1 ����Կ��ʼ���
                nEnd = *(--setKeyPool.end()) + 1; // ��ȡ��ǰ��Կ������Կ��������������������� 1
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey()))) // ����һ����Կ�Բ��ѹ�Կд��Ǯ�����ݿ��ļ���
                throw runtime_error("TopUpKeyPool(): writing generated key failed");
            setKeyPool.insert(nEnd); // ������Կ������������Կ�ؼ���
            LogPrintf("keypool added key %d, size=%u\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet); // Ǯ������

        if (!IsLocked()) // ��Ǯ��δ������
            TopUpKeyPool(); // �ٴ������Կ��

        // Get the oldest key // ��ȡʱ�����������Կ
        if(setKeyPool.empty()) // ����Կ�ؼ���Ϊ��
            return; // ֱ�ӷ���

        CWalletDB walletdb(strWalletFile); // ����Ǯ���ļ�����Ǯ�����ݿ����

        nIndex = *(setKeyPool.begin()); // ��ȡ���ȴ�������Կ������������ 0����СΪ 1
        setKeyPool.erase(setKeyPool.begin()); // ����Կ�ؼ����в�������Կ������
        if (!walletdb.ReadPool(nIndex, keypool)) // ������Կ������Ǯ�����ݿ��ж�ȡһ����Կ����Ŀ
            throw runtime_error("ReserveKeyFromKeyPool(): read failed");
        if (!HaveKey(keypool.vchPubKey.GetID())) // ͨ����ȡ�Ĺ�Կ ID ����Ӧ����Կ�Ƿ����
            throw runtime_error("ReserveKeyFromKeyPool(): unknown key in key pool");
        assert(keypool.vchPubKey.IsValid()); // ��鹫Կ�Ƿ���Ч
        LogPrintf("keypool reserve %d\n", nIndex);
    }
}

void CWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool // ����Կ���Ƴ�ָ����������Կ
    if (fFileBacked) // ��Ǯ���ļ��ѱ���
    {
        CWalletDB walletdb(strWalletFile); // ͨ��Ǯ���ļ�������Ǯ�����ݿ����
        walletdb.ErasePool(nIndex); // ��������������Ӧ����Կ
    }
    LogPrintf("keypool keep %d\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    LogPrintf("keypool return %d\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result)
{
    int64_t nIndex = 0;
    CKeyPool keypool; // ��Կ����Ŀ
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool); // ����Կ����Ԥ��һ����Կ������ȡʧ�ܣ�nIndex Ϊ -1
        if (nIndex == -1) // -1 ��ʾ��ǰ keypool Ϊ��
        {
            if (IsLocked()) return false;
            result = GenerateNewKey(); // �����µ�˽Կ��������Բ���߼������ɶ�Ӧ�Ĺ�Կ
            return true;
        }
        KeepKey(nIndex); // ��Ǯ�����ݿ����Կ�����Ƴ�����Կ
        result = keypool.vchPubKey;
    }
    return true;
}

int64_t CWallet::GetOldestKeyPoolTime()
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

std::map<CTxDestination, CAmount> CWallet::GetAddressBalances()
{
    map<CTxDestination, CAmount> balances; // ��ַ���ӳ���б�

    {
        LOCK(cs_wallet); // Ǯ������
        BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet) // ����Ǯ������ӳ���б�
        { // ��ȡһ��Ǯ����Ŀ������������Ǯ�����ף�
            CWalletTx *pcoin = &walletEntry.second; // ��ȡǮ������

            if (!CheckFinalTx(*pcoin) || !pcoin->IsTrusted()) // Ϊ���ս��� �� ���׿���
                continue; // ����

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0) // ��Ϊ���ҽ��� �� δ����
                continue; // ����

            int nDepth = pcoin->GetDepthInMainChain(); // ��ȡ�ý�������������������
            if (nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) // �����ý��׵�����б�
            {
                CTxDestination addr;
                if (!IsMine(pcoin->vout[i])) // ��������������ҵ�
                    continue; // ����
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, addr)) // �ӽ�������г�ȡ���׵�ַ
                    continue;

                CAmount n = IsSpent(walletEntry.first, i) ? 0 : pcoin->vout[i].nValue; // ���ý���δ���ѣ���ȡ��������ֵ

                if (!balances.count(addr)) // ������в����õ�ַ
                    balances[addr] = 0; // ��ʼ��
                balances[addr] += n; // �ۼӵ�ַ��δ���ѵ�����㣩
            }
        }
    }

    return balances; // ���ص�ַ���ӳ���б�
}

set< set<CTxDestination> > CWallet::GetAddressGroupings()
{
    AssertLockHeld(cs_wallet); // mapWallet
    set< set<CTxDestination> > groupings; // ��ַ���鼯�ϣ�����ַ���ļ��ϣ�
    set<CTxDestination> grouping; // ��ַ���飨��ַ����

    BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet) // ����Ǯ������ӳ���б�
    {
        CWalletTx *pcoin = &walletEntry.second; // ��ȡǮ������

        if (pcoin->vin.size() > 0) // ���ý��׵������б���Ԫ��
        {
            bool any_mine = false;
            // group all input addresses with each other
            BOOST_FOREACH(CTxIn txin, pcoin->vin) // �������������б�
            {
                CTxDestination address;
                if(!IsMine(txin)) /* If this input isn't mine, ignore it */ // �������벻���ҵ�
                    continue; // ����
                if(!ExtractDestination(mapWallet[txin.prevout.hash].vout[txin.prevout.n].scriptPubKey, address)) // �ӽ��������ǰһ�߽�������Ľű���Կ��ȡ��ַ
                    continue; // ʧ������
                grouping.insert(address); // �����ַ����
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine) // �������
            {
               BOOST_FOREACH(CTxOut txout, pcoin->vout) // �����ý��׵�����б�
                   if (IsChange(txout)) // ����Ƿ�Ϊ����
                   {
                       CTxDestination txoutAddr;
                       if(!ExtractDestination(txout.scriptPubKey, txoutAddr)) // �ӽ�������ű���Կ��ȡ���������ַ
                           continue; // ʧ������
                       grouping.insert(txoutAddr); // �����ַ����
                   }
            }
            if (grouping.size() > 0) // ����ַ�������е�ַ
            {
                groupings.insert(grouping); // �����ַ���鼯��
                grouping.clear(); // ͬʱ��ոõ�ַ����
            }
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < pcoin->vout.size(); i++) // �������������б�
            if (IsMine(pcoin->vout[i])) // ������������ҵ�
            {
                CTxDestination address;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, address)) // ������Ľű���Կ��ȡ��ַ
                    continue; // ʧ������
                grouping.insert(address); // �����ַ����
                groupings.insert(grouping); // �����ַ���鼯��
                grouping.clear();
            }
    }

    set< set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    map< CTxDestination, set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    BOOST_FOREACH(set<CTxDestination> grouping, groupings) // �������׵�ַ���鼯��
    {
        // make a set of all the groups hit by this new group
        set< set<CTxDestination>* > hits; // ��ַ����ָ�뼯��
        map< CTxDestination, set<CTxDestination>* >::iterator it;
        BOOST_FOREACH(CTxDestination address, grouping) // ������ַ����
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        set<CTxDestination>* merged = new set<CTxDestination>(grouping);
        BOOST_FOREACH(set<CTxDestination>* hit, hits) // ������ַ����ָ�뼯��
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        BOOST_FOREACH(CTxDestination element, *merged)
            setmap[element] = merged;
    }

    set< set<CTxDestination> > ret;
    BOOST_FOREACH(set<CTxDestination>* uniqueGrouping, uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

std::set<CTxDestination> CWallet::GetAccountAddresses(const std::string& strAccount) const
{
    LOCK(cs_wallet); // Ǯ������
    set<CTxDestination> result; // ����Ŀ�ĵ�ַ��
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& item, mapAddressBook) // ������ַ��ӳ���б�
    {
        const CTxDestination& address = item.first; // ��ȡĿ�ģ������������ַ
        const string& strName = item.second.name; // ��ȡ�˻���
        if (strName == strAccount) // ��Ϊָ���˻���
            result.insert(address); // ���뽻��Ŀ�ĵ�ַ��
    }
    return result; // ���ص�ַ��
}

bool CReserveKey::GetReservedKey(CPubKey& pubkey) // ����Կ����ȡһ����Կ
{
    if (nIndex == -1) // ��ʼ��Ϊ -1
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else {
            return false;
        }
    }
    assert(vchPubKey.IsValid()); // ��⹫Կ����Ч��
    pubkey = vchPubKey;
    return true;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex); // ����Կ�����Ƴ�ָ����������Կ
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex); // ����Կ���·Ż���Կ��
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(set<CKeyID>& setAddress) const
{
    setAddress.clear(); // ��յ�ַ����

    CWalletDB walletdb(strWalletFile); // ����Ǯ�����ݿ����

    LOCK2(cs_main, cs_wallet); // Ǯ������
    BOOST_FOREACH(const int64_t& id, setKeyPool) // ������Կ����������
    {
        CKeyPool keypool; // ����һ����Կ����Ŀ
        if (!walletdb.ReadPool(id, keypool)) // �������������ݿ��ж���Ӧ����Կ����Կ����Ŀ
            throw runtime_error("GetAllReserveKeyHashes(): read failed");
        assert(keypool.vchPubKey.IsValid()); // ������Կ��Ӧ��Կ�Ƿ���Ч
        CKeyID keyID = keypool.vchPubKey.GetID(); // ��ȡ��Կ����
        if (!HaveKey(keyID)) // ����������Ӧ��Կ�Ƿ����
            throw runtime_error("GetAllReserveKeyHashes(): unknown key in key pool");
        setAddress.insert(keyID); // �����ַ����
    }
}

void CWallet::UpdatedTransaction(const uint256 &hashTx)
{
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
    }
}

void CWallet::GetScriptForMining(boost::shared_ptr<CReserveScript> &script)
{
    boost::shared_ptr<CReserveKey> rKey(new CReserveKey(this)); // �½�һ�����������
    CPubKey pubkey;
    if (!rKey->GetReservedKey(pubkey)) // ����Կ����ȡһ����Կ
        return;

    script = rKey; // �����������ֵ��������������� -> ���ࣩ������
    script->reserveScript = CScript() << ToByteVector(pubkey) << OP_CHECKSIG; // �ѹ�Կ����ű�
}

void CWallet::LockCoin(COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.insert(output); // ���������Ľ����������
}

void CWallet::UnlockCoin(COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.erase(output); // ����ָ���Ľ������
}

void CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.clear(); // ��������Ľ����������
}

bool CWallet::IsLockedCoin(uint256 hash, unsigned int n) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    COutPoint outpt(hash, n); // ������������

    return (setLockedCoins.count(outpt) > 0); // ���������Ľ��׼����д��ڣ����� true
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

/** @} */ // end of Actions

class CAffectedKeysVisitor : public boost::static_visitor<void> {
private:
    const CKeyStore &keystore;
    std::vector<CKeyID> &vKeys;

public:
    CAffectedKeysVisitor(const CKeyStore &keystoreIn, std::vector<CKeyID> &vKeysIn) : keystore(keystoreIn), vKeys(vKeysIn) {}

    void Process(const CScript &script) {
        txnouttype type;
        std::vector<CTxDestination> vDest;
        int nRequired;
        if (ExtractDestinations(script, type, vDest, nRequired)) {
            BOOST_FOREACH(const CTxDestination &dest, vDest)
                boost::apply_visitor(*this, dest);
        }
    }

    void operator()(const CKeyID &keyId) {
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    void operator()(const CScriptID &scriptId) {
        CScript script;
        if (keystore.GetCScript(scriptId, script))
            Process(script);
    }

    void operator()(const CNoDestination &none) {}
};

void CWallet::GetKeyBirthTimes(std::map<CKeyID, int64_t> &mapKeyBirth) const {
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    mapKeyBirth.clear(); // �����Կ����ʱ��ӳ���б�

    // get birth times for keys with metadata // ��ȡ��ԿԪ���ݵĴ���ʱ��
    for (std::map<CKeyID, CKeyMetadata>::const_iterator it = mapKeyMetadata.begin(); it != mapKeyMetadata.end(); it++) // ������ԿԪ�����б�
        if (it->second.nCreateTime) // ������ʱ��� 0
            mapKeyBirth[it->first] = it->second.nCreateTime; // ����ӳ��

    // map in which we'll infer heights of other keys
    CBlockIndex *pindexMax = chainActive[std::max(0, chainActive.Height() - 144)]; // the tip can be reorganised; use a 144-block safety margin
    std::map<CKeyID, CBlockIndex*> mapKeyFirstBlock; // ��Կ��������ӳ���б�
    std::set<CKeyID> setKeys; // ��Կ��������
    GetKeys(setKeys);
    BOOST_FOREACH(const CKeyID &keyid, setKeys) { // ��������������
        if (mapKeyBirth.count(keyid) == 0) // ����Կ��������Կ����ʱ��ӳ���б��в�����
            mapKeyFirstBlock[keyid] = pindexMax; // ������Կ��������ӳ���б�
    }
    setKeys.clear(); // �����Կ��������

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty()) // ����Կ��������ӳ���б�Ϊ��
        return;

    // find first block that affects those keys, if there are any left // �ҵ�Ӱ����Щ��Կ���׸����飬�����ʣ��
    std::vector<CKeyID> vAffected;
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); it++) {
        // iterate over all wallet transactions... // ����ȫ��Ǯ������
        const CWalletTx &wtx = (*it).second;
        BlockMap::const_iterator blit = mapBlockIndex.find(wtx.hashBlock);
        if (blit != mapBlockIndex.end() && chainActive.Contains(blit->second)) {
            // ... which are already in a block // �Ѿ���һ������
            int nHeight = blit->second->nHeight;
            BOOST_FOREACH(const CTxOut &txout, wtx.vout) {
                // iterate over all their outputs // ����ȫ�����
                CAffectedKeysVisitor(*this, vAffected).Process(txout.scriptPubKey);
                BOOST_FOREACH(const CKeyID &keyid, vAffected) {
                    // ... and all their affected keys // ��Ӱ���ȫ����Կ
                    std::map<CKeyID, CBlockIndex*>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && nHeight < rit->second->nHeight)
                        rit->second = blit->second;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys // ��ȡ��Щ��Կ������ʱ���
    for (std::map<CKeyID, CBlockIndex*>::const_iterator it = mapKeyFirstBlock.begin(); it != mapKeyFirstBlock.end(); it++)
        mapKeyBirth[it->first] = it->second->GetBlockTime() - 7200; // block times can be 2h off // �Ϳ�ʱ����� 2h
}

bool CWallet::AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    if (boost::get<CNoDestination>(&dest))
        return false;

    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteDestData(CBitcoinAddress(dest).ToString(), key, value);
}

bool CWallet::EraseDestData(const CTxDestination &dest, const std::string &key)
{
    if (!mapAddressBook[dest].destdata.erase(key))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).EraseDestData(CBitcoinAddress(dest).ToString(), key);
}

bool CWallet::LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    return true;
}

bool CWallet::GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const
{
    std::map<CTxDestination, CAddressBookData>::const_iterator i = mapAddressBook.find(dest);
    if(i != mapAddressBook.end())
    {
        CAddressBookData::StringMap::const_iterator j = i->second.destdata.find(key);
        if(j != i->second.destdata.end())
        {
            if(value)
                *value = j->second;
            return true;
        }
    }
    return false;
}

CKeyPool::CKeyPool()
{
    nTime = GetTime();
}

CKeyPool::CKeyPool(const CPubKey& vchPubKeyIn)
{
    nTime = GetTime();
    vchPubKey = vchPubKeyIn;
}

CWalletKey::CWalletKey(int64_t nExpires)
{
    nTimeCreated = (nExpires ? GetTime() : 0);
    nTimeExpires = nExpires;
}

int CMerkleTx::SetMerkleBranch(const CBlock& block)
{
    AssertLockHeld(cs_main);
    CBlock blockTmp;

    // Update the tx's hashBlock
    hashBlock = block.GetHash();

    // Locate the transaction
    for (nIndex = 0; nIndex < (int)block.vtx.size(); nIndex++)
        if (block.vtx[nIndex] == *(CTransaction*)this)
            break;
    if (nIndex == (int)block.vtx.size())
    {
        nIndex = -1;
        LogPrintf("ERROR: SetMerkleBranch(): couldn't find tx in block\n");
        return 0;
    }

    // Is the tx in a block that's in the main chain
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    const CBlockIndex* pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    return chainActive.Height() - pindex->nHeight + 1;
}

int CMerkleTx::GetDepthInMainChain(const CBlockIndex* &pindexRet) const
{
    if (hashUnset()) // �жϸ��������Ч��
        return 0;

    AssertLockHeld(cs_main); // ��֤��״̬

    // Find the block it claims to be in // �ҵ��ý��������ڵ�����
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock); // ��ȡ��Ӧ����ĵ�����
    if (mi == mapBlockIndex.end()) // ��û�ҵ����򷵻� 0
        return 0;
    CBlockIndex* pindex = (*mi).second; // ��ȡ��������
    if (!pindex || !chainActive.Contains(pindex)) // ���������Ƿ��ڼ���������
        return 0;

    pindexRet = pindex;
    return ((nIndex == -1) ? (-1) : 1) * (chainActive.Height() - pindex->nHeight + 1); // ������ȣ���������Ϊ 1
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase()) // �����Ǵ��ҽ���
        return 0;
    return max(0, (COINBASE_MATURITY+1) - GetDepthInMainChain()); // ��ȡ�ݳ��������������
}


bool CMerkleTx::AcceptToMemoryPool(bool fLimitFree, bool fRejectAbsurdFee)
{
    CValidationState state; // ��֤״̬
    return ::AcceptToMemoryPool(mempool, state, *this, fLimitFree, NULL, false, fRejectAbsurdFee); // ��ӽ��׵��ڴ��
}
