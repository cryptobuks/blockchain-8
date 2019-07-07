// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/walletdb.h"

#include "base58.h"
#include "consensus/validation.h"
#include "main.h" // For CheckTransaction
#include "protocol.h"
#include "serialize.h"
#include "sync.h"
#include "util.h"
#include "utiltime.h"
#include "wallet/wallet.h"

#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/thread.hpp>

using namespace std;

static uint64_t nAccountingEntryNumber = 0;

//
// CWalletDB
//

bool CWalletDB::WriteName(const string& strAddress, const string& strName)
{
    nWalletDBUpdated++;
    return Write(make_pair(string("name"), strAddress), strName);
}

bool CWalletDB::EraseName(const string& strAddress)
{
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
    nWalletDBUpdated++;
    return Erase(make_pair(string("name"), strAddress));
}

bool CWalletDB::WritePurpose(const string& strAddress, const string& strPurpose)
{
    nWalletDBUpdated++;
    return Write(make_pair(string("purpose"), strAddress), strPurpose);
}

bool CWalletDB::ErasePurpose(const string& strPurpose)
{
    nWalletDBUpdated++;
    return Erase(make_pair(string("purpose"), strPurpose));
}

bool CWalletDB::WriteTx(uint256 hash, const CWalletTx& wtx)
{
    nWalletDBUpdated++;
    return Write(std::make_pair(std::string("tx"), hash), wtx);
}

bool CWalletDB::EraseTx(uint256 hash)
{
    nWalletDBUpdated++; // Ǯ�����ݿ���´����� 1
    return Erase(std::make_pair(std::string("tx"), hash)); // ����ָ��Ǯ������
}

bool CWalletDB::WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata& keyMeta)
{
    nWalletDBUpdated++;

    if (!Write(std::make_pair(std::string("keymeta"), vchPubKey),
               keyMeta, false))
        return false;

    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> vchKey;
    vchKey.reserve(vchPubKey.size() + vchPrivKey.size());
    vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
    vchKey.insert(vchKey.end(), vchPrivKey.begin(), vchPrivKey.end());

    return Write(std::make_pair(std::string("key"), vchPubKey), std::make_pair(vchPrivKey, Hash(vchKey.begin(), vchKey.end())), false);
}

bool CWalletDB::WriteCryptedKey(const CPubKey& vchPubKey,
                                const std::vector<unsigned char>& vchCryptedSecret,
                                const CKeyMetadata &keyMeta)
{
    const bool fEraseUnencryptedKey = true;
    nWalletDBUpdated++;

    if (!Write(std::make_pair(std::string("keymeta"), vchPubKey),
            keyMeta))
        return false;

    if (!Write(std::make_pair(std::string("ckey"), vchPubKey), vchCryptedSecret, false))
        return false;
    if (fEraseUnencryptedKey)
    {
        Erase(std::make_pair(std::string("key"), vchPubKey));
        Erase(std::make_pair(std::string("wkey"), vchPubKey));
    }
    return true;
}

bool CWalletDB::WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
{
    nWalletDBUpdated++;
    return Write(std::make_pair(std::string("mkey"), nID), kMasterKey, true);
}

bool CWalletDB::WriteCScript(const uint160& hash, const CScript& redeemScript)
{
    nWalletDBUpdated++;
    return Write(std::make_pair(std::string("cscript"), hash), *(const CScriptBase*)(&redeemScript), false);
}

bool CWalletDB::WriteWatchOnly(const CScript &dest)
{
    nWalletDBUpdated++;
    return Write(std::make_pair(std::string("watchs"), *(const CScriptBase*)(&dest)), '1');
}

bool CWalletDB::EraseWatchOnly(const CScript &dest)
{
    nWalletDBUpdated++;
    return Erase(std::make_pair(std::string("watchs"), *(const CScriptBase*)(&dest)));
}

bool CWalletDB::WriteBestBlock(const CBlockLocator& locator)
{
    nWalletDBUpdated++;
    Write(std::string("bestblock"), CBlockLocator()); // Write empty block locator so versions that require a merkle branch automatically rescan
    return Write(std::string("bestblock_nomerkle"), locator);
}

bool CWalletDB::ReadBestBlock(CBlockLocator& locator)
{
    if (Read(std::string("bestblock"), locator) && !locator.vHave.empty()) return true;
    return Read(std::string("bestblock_nomerkle"), locator);
}

bool CWalletDB::WriteOrderPosNext(int64_t nOrderPosNext)
{
    nWalletDBUpdated++; // ���´���
    return Write(std::string("orderposnext"), nOrderPosNext); // ��һ�����׵����д��Ǯ�����ݿ�
}

bool CWalletDB::WriteDefaultKey(const CPubKey& vchPubKey)
{
    nWalletDBUpdated++;
    return Write(std::string("defaultkey"), vchPubKey);
}

bool CWalletDB::ReadPool(int64_t nPool, CKeyPool& keypool)
{
    return Read(std::make_pair(std::string("pool"), nPool), keypool);
}

bool CWalletDB::WritePool(int64_t nPool, const CKeyPool& keypool)
{
    nWalletDBUpdated++; // ���������� 1
    return Write(std::make_pair(std::string("pool"), nPool), keypool); // ���� "pool" ��ǩ��д��Ǯ�����ݿ��ļ�
}

bool CWalletDB::ErasePool(int64_t nPool)
{
    nWalletDBUpdated++; // ���������� 1
    return Erase(std::make_pair(std::string("pool"), nPool)); // ����ָ���������Ƴ�Ǯ�����ݿ��ж�Ӧ����Կ
}

bool CWalletDB::WriteMinVersion(int nVersion)
{
    return Write(std::string("minversion"), nVersion);
}

bool CWalletDB::ReadAccount(const string& strAccount, CAccount& account)
{
    account.SetNull(); // ����˻�����
    return Read(make_pair(string("acc"), strAccount), account); // ��ȡ�� "acc"+�ʻ��� Ϊ�ؼ��ֵ��˻���Ϣ
}

bool CWalletDB::WriteAccount(const string& strAccount, const CAccount& account)
{
    return Write(make_pair(string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry& acentry)
{
    return Write(std::make_pair(std::string("acentry"), std::make_pair(acentry.strAccount, nAccEntryNum)), acentry);
}

bool CWalletDB::WriteAccountingEntry_Backend(const CAccountingEntry& acentry)
{
    return WriteAccountingEntry(++nAccountingEntryNumber, acentry);
}

CAmount CWalletDB::GetAccountCreditDebit(const string& strAccount)
{
    list<CAccountingEntry> entries;
    ListAccountCreditDebit(strAccount, entries);

    CAmount nCreditDebit = 0;
    BOOST_FOREACH (const CAccountingEntry& entry, entries)
        nCreditDebit += entry.nCreditDebit;

    return nCreditDebit;
}

void CWalletDB::ListAccountCreditDebit(const string& strAccount, list<CAccountingEntry>& entries)
{
    bool fAllAccounts = (strAccount == "*");

    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error("CWalletDB::ListAccountCreditDebit(): cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    while (true)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << std::make_pair(std::string("acentry"), std::make_pair((fAllAccounts ? string("") : strAccount), uint64_t(0)));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error("CWalletDB::ListAccountCreditDebit(): error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "acentry")
            break;
        CAccountingEntry acentry;
        ssKey >> acentry.strAccount;
        if (!fAllAccounts && acentry.strAccount != strAccount)
            break;

        ssValue >> acentry;
        ssKey >> acentry.nEntryNo;
        entries.push_back(acentry);
    }

    pcursor->close();
}

DBErrors CWalletDB::ReorderTransactions(CWallet* pwallet)
{
    LOCK(pwallet->cs_wallet);
    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap.
    typedef pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef multimap<int64_t, TxPair > TxItems;
    TxItems txByTime;

    for (map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txByTime.insert(make_pair(wtx->nTimeReceived, TxPair(wtx, (CAccountingEntry*)0)));
    }
    list<CAccountingEntry> acentries;
    ListAccountCreditDebit("", acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txByTime.insert(make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
    }

    int64_t& nOrderPosNext = pwallet->nOrderPosNext;
    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        CAccountingEntry *const pacentry = (*it).second.second;
        int64_t& nOrderPos = (pwtx != 0) ? pwtx->nOrderPos : pacentry->nOrderPos;

        if (nOrderPos == -1)
        {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);

            if (pwtx)
            {
                if (!WriteTx(pwtx->GetHash(), *pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
        else
        {
            int64_t nOrderPosOff = 0;
            BOOST_FOREACH(const int64_t& nOffsetStart, nOrderPosOffsets)
            {
                if (nOrderPos >= nOffsetStart)
                    ++nOrderPosOff;
            }
            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);

            if (!nOrderPosOff)
                continue;

            // Since we're changing the order, write it back
            if (pwtx)
            {
                if (!WriteTx(pwtx->GetHash(), *pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
    }
    WriteOrderPosNext(nOrderPosNext);

    return DB_LOAD_OK;
}

class CWalletScanState {
public:
    unsigned int nKeys;
    unsigned int nCKeys;
    unsigned int nKeyMeta;
    bool fIsEncrypted;
    bool fAnyUnordered;
    int nFileVersion;
    vector<uint256> vWalletUpgrade;

    CWalletScanState() {
        nKeys = nCKeys = nKeyMeta = 0;
        fIsEncrypted = false;
        fAnyUnordered = false;
        nFileVersion = 0;
    }
};

bool
ReadKeyValue(CWallet* pwallet, CDataStream& ssKey, CDataStream& ssValue,
             CWalletScanState &wss, string& strType, string& strErr)
{
    try {
        // Unserialize // �����л�
        // Taking advantage of the fact that pair serialization // �������л�����ʵ
        // is just the two items serialized one after the other // ֻ������һ����һ������Ŀ
        ssKey >> strType; // ������������
        if (strType == "name") // �����͵����������Ӧ��ֵ��Ǯ��
        {
            string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[CBitcoinAddress(strAddress).Get()].name;
        }
        else if (strType == "purpose")
        {
            string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[CBitcoinAddress(strAddress).Get()].purpose;
        }
        else if (strType == "tx")
        {
            uint256 hash;
            ssKey >> hash;
            CWalletTx wtx;
            ssValue >> wtx;
            CValidationState state;
            if (!(CheckTransaction(wtx, state) && (wtx.GetHash() == hash) && state.IsValid()))
                return false;

            // Undo serialize changes in 31600
            if (31404 <= wtx.fTimeReceivedIsTxTime && wtx.fTimeReceivedIsTxTime <= 31703)
            {
                if (!ssValue.empty())
                {
                    char fTmp;
                    char fUnused;
                    ssValue >> fTmp >> fUnused >> wtx.strFromAccount;
                    strErr = strprintf("LoadWallet() upgrading tx ver=%d %d '%s' %s",
                                       wtx.fTimeReceivedIsTxTime, fTmp, wtx.strFromAccount, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = fTmp;
                }
                else
                {
                    strErr = strprintf("LoadWallet() repairing tx ver=%d %s", wtx.fTimeReceivedIsTxTime, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = 0;
                }
                wss.vWalletUpgrade.push_back(hash);
            }

            if (wtx.nOrderPos == -1)
                wss.fAnyUnordered = true;

            pwallet->AddToWallet(wtx, true, NULL);
        }
        else if (strType == "acentry")
        {
            string strAccount;
            ssKey >> strAccount;
            uint64_t nNumber;
            ssKey >> nNumber;
            if (nNumber > nAccountingEntryNumber)
                nAccountingEntryNumber = nNumber;

            if (!wss.fAnyUnordered)
            {
                CAccountingEntry acentry;
                ssValue >> acentry;
                if (acentry.nOrderPos == -1)
                    wss.fAnyUnordered = true;
            }
        }
        else if (strType == "watchs")
        {
            CScript script;
            ssKey >> *(CScriptBase*)(&script);
            char fYes;
            ssValue >> fYes;
            if (fYes == '1')
                pwallet->LoadWatchOnly(script);

            // Watch-only addresses have no birthday information for now,
            // so set the wallet birthday to the beginning of time.
            pwallet->nTimeFirstKey = 1;
        }
        else if (strType == "key" || strType == "wkey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            CKey key;
            CPrivKey pkey;
            uint256 hash;

            if (strType == "key")
            {
                wss.nKeys++;
                ssValue >> pkey;
            } else {
                CWalletKey wkey;
                ssValue >> wkey;
                pkey = wkey.vchPrivKey;
            }

            // Old wallets store keys as "key" [pubkey] => [privkey]
            // ... which was slow for wallets with lots of keys, because the public key is re-derived from the private key
            // using EC operations as a checksum.
            // Newer wallets store keys as "key"[pubkey] => [privkey][hash(pubkey,privkey)], which is much faster while
            // remaining backwards-compatible.
            try
            {
                ssValue >> hash;
            }
            catch (...) {}

            bool fSkipCheck = false;

            if (!hash.IsNull())
            {
                // hash pubkey/privkey to accelerate wallet load
                std::vector<unsigned char> vchKey;
                vchKey.reserve(vchPubKey.size() + pkey.size());
                vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
                vchKey.insert(vchKey.end(), pkey.begin(), pkey.end());

                if (Hash(vchKey.begin(), vchKey.end()) != hash)
                {
                    strErr = "Error reading wallet database: CPubKey/CPrivKey corrupt";
                    return false;
                }

                fSkipCheck = true;
            }

            if (!key.Load(pkey, vchPubKey, fSkipCheck))
            {
                strErr = "Error reading wallet database: CPrivKey corrupt";
                return false;
            }
            if (!pwallet->LoadKey(key, vchPubKey))
            {
                strErr = "Error reading wallet database: LoadKey failed";
                return false;
            }
        }
        else if (strType == "mkey")
        {
            unsigned int nID;
            ssKey >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if(pwallet->mapMasterKeys.count(nID) != 0)
            {
                strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
                return false;
            }
            pwallet->mapMasterKeys[nID] = kMasterKey;
            if (pwallet->nMasterKeyMaxID < nID)
                pwallet->nMasterKeyMaxID = nID;
        }
        else if (strType == "ckey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            vector<unsigned char> vchPrivKey;
            ssValue >> vchPrivKey;
            wss.nCKeys++;

            if (!pwallet->LoadCryptedKey(vchPubKey, vchPrivKey))
            {
                strErr = "Error reading wallet database: LoadCryptedKey failed";
                return false;
            }
            wss.fIsEncrypted = true;
        }
        else if (strType == "keymeta")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            CKeyMetadata keyMeta;
            ssValue >> keyMeta;
            wss.nKeyMeta++;

            pwallet->LoadKeyMetadata(vchPubKey, keyMeta);

            // find earliest key creation time, as wallet birthday
            if (!pwallet->nTimeFirstKey ||
                (keyMeta.nCreateTime < pwallet->nTimeFirstKey))
                pwallet->nTimeFirstKey = keyMeta.nCreateTime;
        }
        else if (strType == "defaultkey")
        {
            ssValue >> pwallet->vchDefaultKey;
        }
        else if (strType == "pool")
        {
            int64_t nIndex;
            ssKey >> nIndex;
            CKeyPool keypool;
            ssValue >> keypool;
            pwallet->setKeyPool.insert(nIndex);

            // If no metadata exists yet, create a default with the pool key's
            // creation time. Note that this may be overwritten by actually
            // stored metadata for that key later, which is fine.
            CKeyID keyid = keypool.vchPubKey.GetID();
            if (pwallet->mapKeyMetadata.count(keyid) == 0)
                pwallet->mapKeyMetadata[keyid] = CKeyMetadata(keypool.nTime);
        }
        else if (strType == "version")
        {
            ssValue >> wss.nFileVersion;
            if (wss.nFileVersion == 10300)
                wss.nFileVersion = 300;
        }
        else if (strType == "cscript")
        {
            uint160 hash;
            ssKey >> hash;
            CScript script;
            ssValue >> *(CScriptBase*)(&script);
            if (!pwallet->LoadCScript(script))
            {
                strErr = "Error reading wallet database: LoadCScript failed";
                return false;
            }
        }
        else if (strType == "orderposnext")
        {
            ssValue >> pwallet->nOrderPosNext;
        }
        else if (strType == "destdata")
        {
            std::string strAddress, strKey, strValue;
            ssKey >> strAddress;
            ssKey >> strKey;
            ssValue >> strValue;
            if (!pwallet->LoadDestData(CBitcoinAddress(strAddress).Get(), strKey, strValue))
            {
                strErr = "Error reading wallet database: LoadDestData failed";
                return false;
            }
        }
    } catch (...)
    {
        return false; // �����л�ʧ�ܷ��� false
    }
    return true; // �ɹ����� true
}

static bool IsKeyType(string strType)
{
    return (strType== "key" || strType == "wkey" ||
            strType == "mkey" || strType == "ckey");
}

DBErrors CWalletDB::LoadWallet(CWallet* pwallet)
{
    pwallet->vchDefaultKey = CPubKey(); // ��ʼ��Ǯ��Ĭ�Ϲ�Կ
    CWalletScanState wss; // ��¼Ǯ��ɨ��״̬
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK; // ����Ǯ����״̬��Ĭ��Ϊ 0����ʾ�ɹ�

    try {
        LOCK(pwallet->cs_wallet);
        int nMinVersion = 0;
        if (Read((string)"minversion", nMinVersion))
        {
            if (nMinVersion > CLIENT_VERSION)
                return DB_TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Get cursor
        Dbc* pcursor = GetCursor(); // ��ȡǮ�����ݿ��α�
        if (!pcursor)
        {
            LogPrintf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true) // ��������ȡÿһ����¼
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION); // ��
            CDataStream ssValue(SER_DISK, CLIENT_VERSION); // ֵ
            int ret = ReadAtCursor(pcursor, ssKey, ssValue); // ���α��λ�û�ȡһ����¼����ֵ�ԣ�
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0) // 0 ��ʾ��ȡ�ɹ�
            {
                LogPrintf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            // Try to be tolerant of single corrupt records:
            string strType, strErr; // �������̵�һ�Ĵ����¼
            if (!ReadKeyValue(pwallet, ssKey, ssValue, wss, strType, strErr)) // ������ֵ��Ǯ��
            {
                // losing keys is considered a catastrophic error, anything else // ��ʧ��Կ����Ϊ�������ԵĴ���
                // we assume the user can live with: // ���Ǽ����û���������������
                if (IsKeyType(strType)) // ������Կ����
                    result = DB_CORRUPT; // 1 ��ʾ����
                else
                {
                    // Leave other errors alone, if we try to fix them we might make things worse.
                    fNoncriticalErrors = true; // ... but do warn the user there is something wrong.
                    if (strType == "tx") // �������һ�������׼�¼
                        // Rescan if there is a bad transaction record:
                        SoftSetBoolArg("-rescan", true); // ����������
                }
            }
            if (!strErr.empty()) // ����Ƿ��д���
                LogPrintf("%s\n", strErr); // ����¼
        }
        pcursor->close(); // �ر�Ǯ�����ݿ�
    }
    catch (const boost::thread_interrupted&) {
        throw;
    }
    catch (...) {
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK)
        result = DB_NONCRITICAL_ERROR;

    // Any wallet corruption at all: skip any rewriting or
    // upgrading, we don't want to make it worse.
    if (result != DB_LOAD_OK) // �κ�Ǯ����������������д�����������ǲ���������ø���
        return result;

    LogPrintf("nFileVersion = %d\n", wss.nFileVersion); // ��¼�ļ��汾

    LogPrintf("Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total\n",
           wss.nKeys, wss.nCKeys, wss.nKeyMeta, wss.nKeys + wss.nCKeys);

    // nTimeFirstKey is only reliable if all keys have metadata
    if ((wss.nKeys + wss.nCKeys) != wss.nKeyMeta)
        pwallet->nTimeFirstKey = 1; // 0 would be considered 'no value'

    BOOST_FOREACH(uint256 hash, wss.vWalletUpgrade)
        WriteTx(hash, pwallet->mapWallet[hash]);

    // Rewrite encrypted wallets of versions 0.4.0 and 0.5.0rc:
    if (wss.fIsEncrypted && (wss.nFileVersion == 40000 || wss.nFileVersion == 50000))
        return DB_NEED_REWRITE;

    if (wss.nFileVersion < CLIENT_VERSION) // Update
        WriteVersion(CLIENT_VERSION);

    if (wss.fAnyUnordered)
        result = ReorderTransactions(pwallet);

    pwallet->laccentries.clear();
    ListAccountCreditDebit("*", pwallet->laccentries);
    BOOST_FOREACH(CAccountingEntry& entry, pwallet->laccentries) {
        pwallet->wtxOrdered.insert(make_pair(entry.nOrderPos, CWallet::TxPair((CWalletTx*)0, &entry)));
    }

    return result;
}

DBErrors CWalletDB::FindWalletTx(CWallet* pwallet, vector<uint256>& vTxHash, vector<CWalletTx>& vWtx)
{
    pwallet->vchDefaultKey = CPubKey();
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try {
        LOCK(pwallet->cs_wallet);
        int nMinVersion = 0;
        if (Read((string)"minversion", nMinVersion))
        {
            if (nMinVersion > CLIENT_VERSION)
                return DB_TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
        {
            LogPrintf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                LogPrintf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            string strType;
            ssKey >> strType;
            if (strType == "tx") {
                uint256 hash;
                ssKey >> hash;

                CWalletTx wtx;
                ssValue >> wtx;

                vTxHash.push_back(hash);
                vWtx.push_back(wtx);
            }
        }
        pcursor->close();
    }
    catch (const boost::thread_interrupted&) {
        throw;
    }
    catch (...) {
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK)
        result = DB_NONCRITICAL_ERROR;

    return result;
}

DBErrors CWalletDB::ZapWalletTx(CWallet* pwallet, vector<CWalletTx>& vWtx)
{
    // build list of wallet TXs // ����Ǯ�������б�
    vector<uint256> vTxHash;
    DBErrors err = FindWalletTx(pwallet, vTxHash, vWtx); // ��ѯ����ȡָ��Ǯ����Ǯ�����׹�ϣ�ͽ��׶���
    if (err != DB_LOAD_OK)
        return err;

    // erase each wallet TX // ����ÿ��Ǯ������
    BOOST_FOREACH (uint256& hash, vTxHash) { // ����Ǯ�����׹�ϣ�б�
        if (!EraseTx(hash)) // �������ݿ��е�Ǯ������
            return DB_CORRUPT;
    }

    return DB_LOAD_OK;
}

void ThreadFlushWalletDB(const string& strFile)
{
    // Make this thread recognisable as the wallet flushing thread
    RenameThread("bitcoin-wallet"); // �������߳�

    static bool fOneThread;
    if (fOneThread) // ���߳�ֻ�ܴ���һ��
        return;
    fOneThread = true;
    if (!GetBoolArg("-flushwallet", DEFAULT_FLUSHWALLET)) // ˢ��Ǯ����־��Ĭ�ϴ�
        return;

    unsigned int nLastSeen = nWalletDBUpdated;
    unsigned int nLastFlushed = nWalletDBUpdated;
    int64_t nLastWalletUpdate = GetTime();
    while (true) // ÿ 500 ����ˢ��һ��
    {
        MilliSleep(500);

        if (nLastSeen != nWalletDBUpdated)
        {
            nLastSeen = nWalletDBUpdated;
            nLastWalletUpdate = GetTime();
        }

        if (nLastFlushed != nWalletDBUpdated && GetTime() - nLastWalletUpdate >= 2) // ���µ�ʱ�������ڵ��� 2 ��
        {
            TRY_LOCK(bitdb.cs_db,lockDb);
            if (lockDb)
            {
                // Don't do this if any databases are in use
                int nRefCount = 0; // ����Ǯ�����ݿ��ļ������ü���
                map<string, int>::iterator mi = bitdb.mapFileUseCount.begin();
                while (mi != bitdb.mapFileUseCount.end())
                {
                    nRefCount += (*mi).second;
                    mi++;
                }

                if (nRefCount == 0) // �����ü���Ϊ 0 ʱ��ˢ��Ǯ������
                {
                    boost::this_thread::interruption_point();
                    map<string, int>::iterator mi = bitdb.mapFileUseCount.find(strFile);
                    if (mi != bitdb.mapFileUseCount.end())
                    {
                        LogPrint("db", "Flushing wallet.dat\n");
                        nLastFlushed = nWalletDBUpdated;
                        int64_t nStart = GetTimeMillis();

                        // Flush wallet.dat so it's self contained
                        bitdb.CloseDb(strFile); // ������ˢ�£�ͨ���ر����ݿ��ļ���ʵ�����ݱ��ػ�
                        bitdb.CheckpointLSN(strFile); // ���ü���

                        bitdb.mapFileUseCount.erase(mi++);
                        LogPrint("db", "Flushed wallet.dat %dms\n", GetTimeMillis() - nStart);
                    }
                }
            }
        }
    }
}

bool BackupWallet(const CWallet& wallet, const string& strDest)
{
    if (!wallet.fFileBacked) // �����ļ���־Ϊ true
        return false;
    while (true)
    {
        {
            LOCK(bitdb.cs_db); // ���ݿ�����
            if (!bitdb.mapFileUseCount.count(wallet.strWalletFile) || bitdb.mapFileUseCount[wallet.strWalletFile] == 0) // �ļ���δʹ�ù� �� �ļ������ڵ�ʹ�ô���Ϊ 0
            {
                // Flush log data to the dat file // ˢ����־���ݵ������ļ�
                bitdb.CloseDb(wallet.strWalletFile);
                bitdb.CheckpointLSN(wallet.strWalletFile);
                bitdb.mapFileUseCount.erase(wallet.strWalletFile);

                // Copy wallet.dat // ���� wallet.dat �ļ�
                boost::filesystem::path pathSrc = GetDataDir() / wallet.strWalletFile; // ԭ wallet.dat ·��
                boost::filesystem::path pathDest(strDest); // Ŀ��·��
                if (boost::filesystem::is_directory(pathDest)) // ��Ŀ��·��ΪĿ¼
                    pathDest /= wallet.strWalletFile; // ƴ��Ĭ��Ǯ���ļ��� "wallet.dat"

                try {
#if BOOST_VERSION >= 104000 // boost �汾Ϊ 104000 ֮��
                    boost::filesystem::copy_file(pathSrc, pathDest, boost::filesystem::copy_option::overwrite_if_exists); // copy �ļ���Ŀ��λ�ã����ļ��Ѵ����򸲸�
#else
                    boost::filesystem::copy_file(pathSrc, pathDest); // copy �ļ���Ŀ��λ��
#endif
                    LogPrintf("copied wallet.dat to %s\n", pathDest.string()); // ��¼��־
                    return true;
                } catch (const boost::filesystem::filesystem_error& e) {
                    LogPrintf("error copying wallet.dat to %s - %s\n", pathDest.string(), e.what());
                    return false;
                }
            }
        }
        MilliSleep(100); // ˯ 100 ����
    }
    return false;
}

//
// Try to (very carefully!) recover wallet.dat if there is a problem.
// // ����������⣬���ԣ��ǳ�С�ģ����ָ� wallet.dat��
bool CWalletDB::Recover(CDBEnv& dbenv, const std::string& filename, bool fOnlyKeys)
{
    // Recovery procedure: // �ָ����裺
    // move wallet.dat to wallet.timestamp.bak // 1.������Ǯ���ļ� wallet.dat Ϊ wallet.timestamp.bak
    // Call Salvage with fAggressive=true to // 2.���� Salvage �������Ǯ�����ݣ�fAggressive ��־��Ϊ true����ʾ���� DB_AGGRESSIVE ģʽ
    // get as much data as possible. // ���ܻ�ȡ��������ݡ�
    // Rewrite salvaged data to wallet.dat // 3.��д��ȵ����ݵ� wallet.dat
    // Set -rescan so any missing transactions will be // 4.���� -rescan �Ա��һ�ȫ����ʧ�Ľ��ס�
    // found.
    int64_t now = GetTime(); // ��ȡ��ǰ��ʱ���
    std::string newFilename = strprintf("wallet.%d.bak", now); // 1.ƴ�����ݿⱸ���ļ���

    int result = dbenv.dbenv->dbrename(NULL, filename.c_str(), NULL,
                                       newFilename.c_str(), DB_AUTO_COMMIT); // ���ݿ��ļ�������
    if (result == 0) // rename �ɹ�
        LogPrintf("Renamed %s to %s\n", filename, newFilename); // ��¼��־
    else
    {
        LogPrintf("Failed to rename %s to %s\n", filename, newFilename);
        return false;
    }

    std::vector<CDBEnv::KeyValPair> salvagedData; // 2.������ݣ�KV ��ֵ���б�
    bool fSuccess = dbenv.Salvage(newFilename, true, salvagedData); // ���Ǯ������ȡ��ȵ�����
    if (salvagedData.empty()) // ����ȵ�����Ϊ��
    {
        LogPrintf("Salvage(aggressive) found no records in %s.\n", newFilename); // ����û�������ļ����ҵ���¼
        return false;
    }
    LogPrintf("Salvage(aggressive) found %u records\n", salvagedData.size()); // ��¼������ݵĴ�С

    boost::scoped_ptr<Db> pdbCopy(new Db(dbenv.dbenv, 0)); // 3.�������ݿ⸱���Ѷ��󣬲��� Berkeley DB
    int ret = pdbCopy->open(NULL,               // Txn pointer
                            filename.c_str(),   // Filename // e.g. "xx/wallet.dat"
                            "main",             // Logical db name
                            DB_BTREE,           // Database type
                            DB_CREATE,          // Flags
                            0);
    if (ret > 0)
    {
        LogPrintf("Cannot create database file %s\n", filename);
        return false;
    }
    CWallet dummyWallet; // 4.��Ǯ��
    CWalletScanState wss; // Ǯ��ɨ��״̬

    DbTxn* ptxn = dbenv.TxnBegin(); // ����ָ��ָ���׼��еĵ�һ�ʽ���
    BOOST_FOREACH(CDBEnv::KeyValPair& row, salvagedData) // ������ȡ��ȵ����ݵ�һ��
    {
        if (fOnlyKeys) // true
        {
            CDataStream ssKey(row.first, SER_DISK, CLIENT_VERSION); // key
            CDataStream ssValue(row.second, SER_DISK, CLIENT_VERSION); // value
            string strType, strErr;
            bool fReadOK;
            {
                // Required in LoadKeyMetadata(): // ��Ҫ LoadKeyMetadata()��
                LOCK(dummyWallet.cs_wallet); // ��Ǯ������
                fReadOK = ReadKeyValue(&dummyWallet, ssKey, ssValue,
                                        wss, strType, strErr); // ��һ����ֵ�ԣ������л��������Ǯ�����ڴ棩������ȡ��������
            }
            if (!IsKeyType(strType)) // �� Key ����
                continue;
            if (!fReadOK)
            {
                LogPrintf("WARNING: CWalletDB::Recover skipping %s: %s\n", strType, strErr);
                continue;
            }
        }
        Dbt datKey(&row.first[0], row.first.size()); // ���ݿ��
        Dbt datValue(&row.second[0], row.second.size()); // ���ݿ�ֵ
        int ret2 = pdbCopy->put(ptxn, &datKey, &datValue, DB_NOOVERWRITE); // �������ݿ⸱�����ļ���
        if (ret2 > 0)
            fSuccess = false;
    }
    ptxn->commit(0); // 5.�ύ���ף��޸ĵ����ݽ�д���ȶ����ڴ�
    pdbCopy->close(0); // �ر����ݿ⸱��

    return fSuccess; // �ɹ����� true
}

bool CWalletDB::Recover(CDBEnv& dbenv, const std::string& filename)
{
    return CWalletDB::Recover(dbenv, filename, false);
}

bool CWalletDB::WriteDestData(const std::string &address, const std::string &key, const std::string &value)
{
    nWalletDBUpdated++;
    return Write(std::make_pair(std::string("destdata"), std::make_pair(address, key)), value);
}

bool CWalletDB::EraseDestData(const std::string &address, const std::string &key)
{
    nWalletDBUpdated++;
    return Erase(std::make_pair(std::string("destdata"), std::make_pair(address, key)));
}
