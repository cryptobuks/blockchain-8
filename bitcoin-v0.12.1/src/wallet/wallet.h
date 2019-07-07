// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLET_H
#define BITCOIN_WALLET_WALLET_H

#include "amount.h"
#include "streams.h"
#include "tinyformat.h"
#include "ui_interface.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#include "wallet/crypter.h"
#include "wallet/wallet_ismine.h"
#include "wallet/walletdb.h"

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <boost/shared_ptr.hpp>

/**
 * Settings
 */
extern CFeeRate payTxFee;
extern CAmount maxTxFee;
extern unsigned int nTxConfirmTarget;
extern bool bSpendZeroConfChange;
extern bool fSendFreeTransactions;

static const unsigned int DEFAULT_KEYPOOL_SIZE = 100; // ��Կ��Ĭ�ϴ�С
//! -paytxfee default
static const CAmount DEFAULT_TRANSACTION_FEE = 0;
//! -paytxfee will warn if called with a higher fee than this amount (in satoshis) per KB
static const CAmount nHighTransactionFeeWarning = 0.01 * COIN;
//! -fallbackfee default
static const CAmount DEFAULT_FALLBACK_FEE = 20000;
//! -mintxfee default
static const CAmount DEFAULT_TRANSACTION_MINFEE = 1000;
//! -maxtxfee default
static const CAmount DEFAULT_TRANSACTION_MAXFEE = 0.1 * COIN;
//! minimum change amount
static const CAmount MIN_CHANGE = CENT;
//! Default for -spendzeroconfchange
static const bool DEFAULT_SPEND_ZEROCONF_CHANGE = true;
//! Default for -sendfreetransactions // Ĭ��ͨ�� -sendfreetransactions ѡ������
static const bool DEFAULT_SEND_FREE_TRANSACTIONS = false; // Ĭ����ѷ��ͽ��ף�Ĭ�Ϲر�
//! -txconfirmtarget default
static const unsigned int DEFAULT_TX_CONFIRM_TARGET = 2;
//! -maxtxfee will warn if called with a higher fee than this amount (in satoshis)
static const CAmount nHighTransactionMaxFeeWarning = 100 * nHighTransactionFeeWarning;
//! Largest (in bytes) free transaction we're willing to create // ����ϣ��������������ֽ�Ϊ��λ����ѽ���
static const unsigned int MAX_FREE_TRANSACTION_CREATE_SIZE = 1000; // �����������ѽ��״�С��1000B��
static const bool DEFAULT_WALLETBROADCAST = true; // Ǯ�����׹㲥��Ĭ�Ͽ���

class CAccountingEntry;
class CBlockIndex;
class CCoinControl;
class COutput;
class CReserveKey;
class CScript;
class CTxMemPool;
class CWalletTx;

/** (client) version numbers for particular wallet features */
enum WalletFeature
{
    FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000, // wallet encryption
    FEATURE_COMPRPUBKEY = 60000, // compressed public keys

    FEATURE_LATEST = 60000
};


/** A key pool entry */
class CKeyPool // һ����Կ����Ŀ�����湫Կ��
{
public:
    int64_t nTime; // ʱ��
    CPubKey vchPubKey; // ��Կ

    CKeyPool();
    CKeyPool(const CPubKey& vchPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(nTime);
        READWRITE(vchPubKey);
    }
};

/** Address book data */
class CAddressBookData // ��ַ������
{
public:
    std::string name; // �����˻���
    std::string purpose; // ��; / Ŀ��

    CAddressBookData()
    {
        purpose = "unknown";
    }

    typedef std::map<std::string, std::string> StringMap;
    StringMap destdata;
};

struct CRecipient // ������
{
    CScript scriptPubKey; // ��Կ�ű�
    CAmount nAmount; // ���
    bool fSubtractFeeFromAmount; // �ý���Ƿ��ȥ���׷ѵı�־
};

typedef std::map<std::string, std::string> mapValue_t;


static void ReadOrderPos(int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (!mapValue.count("n"))
    {
        nOrderPos = -1; // TODO: calculate elsewhere
        return;
    }
    nOrderPos = atoi64(mapValue["n"].c_str());
}


static void WriteOrderPos(const int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (nOrderPos == -1)
        return;
    mapValue["n"] = i64tostr(nOrderPos);
}

struct COutputEntry // �����Ŀ
{
    CTxDestination destination; // ����Ŀ�ĵ�
    CAmount amount; // ���
    int vout; // �������
};

/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx : public CTransaction // һ������������������Ĭ�˷�֧����
{
private:
  /** Constant used in hashBlock to indicate tx has been abandoned */
    static const uint256 ABANDON_HASH; // �ڿ��ϣ��ʹ�õ����ڱ�ʾ�����ѱ������ĳ���

public:
    uint256 hashBlock; // ���ϣ

    /* An nIndex == -1 means that hashBlock (in nonzero) refers to the earliest
     * block in the chain we know this or any in-wallet dependency conflicts
     * with. Older clients interpret nIndex == -1 as unconfirmed for backward
     * compatibility.
     */ // nIndex ���� -1 ��ζ�ſ��ϣ�����㣩ָ������������Ŀ飬����֪��������κ�Ǯ���ڲ�������ͻ���ɿͻ��˰� nIndex ���� -1 ����Ϊδȷ�����ļ����ԡ�
    int nIndex;

    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = uint256();
        nIndex = -1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        std::vector<uint256> vMerkleBranch; // For compatibility with older versions.
        READWRITE(*(CTransaction*)this);
        nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    int SetMerkleBranch(const CBlock& block);

    /**
     * Return depth of transaction in blockchain:
     * <0  : conflicts with a transaction this deep in the blockchain
     *  0  : in memory pool, waiting to be included in a block
     * >=1 : this many blocks deep in the main chain
     */ // ���ؽ��������������������ϵ���ȣ�<0:���������н��׳�ͻ��==0:���ڴ���У�δ���������ȴ����������飻>=1:�������кܶ�����
    int GetDepthInMainChain(const CBlockIndex* &pindexRet) const; // ��ȡ�ý����������ϵ����
    int GetDepthInMainChain() const { const CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet); }
    bool IsInMainChain() const { const CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet) > 0; }
    int GetBlocksToMaturity() const; // ��ȡ�ݳ����������������101 - ��ǰ�������������
    bool AcceptToMemoryPool(bool fLimitFree=true, bool fRejectAbsurdFee=true); // �ѵ�ǰ������ӵ��ڴ��
    bool hashUnset() const { return (hashBlock.IsNull() || hashBlock == ABANDON_HASH); } // ��ϣδ���ã�Ϊ�ջ��������Ĺ�ϣ��
    bool isAbandoned() const { return (hashBlock == ABANDON_HASH); } // �ý����Ƿ���Ϊ������
    void setAbandoned() { hashBlock = ABANDON_HASH; } // ��Ǹý���Ϊ������
};

/** 
 * A transaction with a bunch of additional info that only the owner cares about.
 * It includes any unrecorded transactions needed to link it back to the block chain.
 */ // һϵ��ֻ�������߲Ź��ĵĽ��׵ĸ�����Ϣ��������ȫ����Ҫ���ӻ���������δ��¼�Ľ��ס�
class CWalletTx : public CMerkleTx // Ǯ������
{
private:
    const CWallet* pwallet; // Ǯ��ָ��

public:
    mapValue_t mapValue;
    std::vector<std::pair<std::string, std::string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived; //! time received by this node
    unsigned int nTimeSmart;
    char fFromMe; // ���״��Լ������ı�־
    std::string strFromAccount; // �ý����Ǵ��ĸ��˻�����
    int64_t nOrderPos; //! position in ordered transaction list // ������Ľ����б��е�λ��

    // memory only
    mutable bool fDebitCached;
    mutable bool fCreditCached;
    mutable bool fImmatureCreditCached;
    mutable bool fAvailableCreditCached; // ���������ʶ
    mutable bool fWatchDebitCached;
    mutable bool fWatchCreditCached;
    mutable bool fImmatureWatchCreditCached;
    mutable bool fAvailableWatchCreditCached;
    mutable bool fChangeCached;
    mutable CAmount nDebitCached;
    mutable CAmount nCreditCached;
    mutable CAmount nImmatureCreditCached;
    mutable CAmount nAvailableCreditCached; // ����Ŀ��õģ����ŵģ����
    mutable CAmount nWatchDebitCached;
    mutable CAmount nWatchCreditCached;
    mutable CAmount nImmatureWatchCreditCached;
    mutable CAmount nAvailableWatchCreditCached;
    mutable CAmount nChangeCached;

    CWalletTx()
    {
        Init(NULL);
    }

    CWalletTx(const CWallet* pwalletIn)
    {
        Init(pwalletIn);
    }

    CWalletTx(const CWallet* pwalletIn, const CMerkleTx& txIn) : CMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    CWalletTx(const CWallet* pwalletIn, const CTransaction& txIn) : CMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    void Init(const CWallet* pwalletIn)
    {
        pwallet = pwalletIn;
        mapValue.clear();
        vOrderForm.clear();
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        nTimeSmart = 0;
        fFromMe = false;
        strFromAccount.clear();
        fDebitCached = false;
        fCreditCached = false;
        fImmatureCreditCached = false;
        fAvailableCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fChangeCached = false;
        nDebitCached = 0;
        nCreditCached = 0;
        nImmatureCreditCached = 0;
        nAvailableCreditCached = 0;
        nWatchDebitCached = 0;
        nWatchCreditCached = 0;
        nAvailableWatchCreditCached = 0;
        nImmatureWatchCreditCached = 0;
        nChangeCached = 0;
        nOrderPos = -1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        if (ser_action.ForRead())
            Init(NULL);
        char fSpent = false;

        if (!ser_action.ForRead())
        {
            mapValue["fromaccount"] = strFromAccount;

            WriteOrderPos(nOrderPos, mapValue);

            if (nTimeSmart)
                mapValue["timesmart"] = strprintf("%u", nTimeSmart);
        }

        READWRITE(*(CMerkleTx*)this);
        std::vector<CMerkleTx> vUnused; //! Used to be vtxPrev
        READWRITE(vUnused);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);

        if (ser_action.ForRead())
        {
            strFromAccount = mapValue["fromaccount"];

            ReadOrderPos(nOrderPos, mapValue);

            nTimeSmart = mapValue.count("timesmart") ? (unsigned int)atoi64(mapValue["timesmart"]) : 0;
        }

        mapValue.erase("fromaccount");
        mapValue.erase("version");
        mapValue.erase("spent");
        mapValue.erase("n");
        mapValue.erase("timesmart");
    }

    //! make sure balances are recalculated // ȷ�������¼���
    void MarkDirty() // ����ѱ䶯
    {
        fCreditCached = false;
        fAvailableCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fDebitCached = false;
        fChangeCached = false;
    }

    void BindWallet(CWallet *pwalletIn)
    {
        pwallet = pwalletIn;
        MarkDirty();
    }

    //! filter decides which addresses will count towards the debit // ������������Щ��ַ���������
    CAmount GetDebit(const isminefilter& filter) const;
    CAmount GetCredit(const isminefilter& filter) const;
    CAmount GetImmatureCredit(bool fUseCache=true) const;
    CAmount GetAvailableCredit(bool fUseCache=true) const; // ��ȡ���õĽ�Ĭ��ʹ�û��棩
    CAmount GetImmatureWatchOnlyCredit(const bool& fUseCache=true) const;
    CAmount GetAvailableWatchOnlyCredit(const bool& fUseCache=true) const;
    CAmount GetChange() const;

    void GetAmounts(std::list<COutputEntry>& listReceived,
                    std::list<COutputEntry>& listSent, CAmount& nFee, std::string& strSentAccount, const isminefilter& filter) const;

    void GetAccountAmounts(const std::string& strAccount, CAmount& nReceived,
                           CAmount& nSent, CAmount& nFee, const isminefilter& filter) const;

    bool IsFromMe(const isminefilter& filter) const
    {
        return (GetDebit(filter) > 0);
    }

    // True if only scriptSigs are different
    bool IsEquivalentTo(const CWalletTx& tx) const;

    bool InMempool() const;
    bool IsTrusted() const; // �����Ǯ�����׵�������������ڴ���У���Ϊ����

    bool WriteToDisk(CWalletDB *pwalletdb);

    int64_t GetTxTime() const;
    int GetRequestCount() const;

    bool RelayWalletTransaction();

    std::set<uint256> GetConflicts() const;
};




class COutput // ���
{
public:
    const CWalletTx *tx; // Ǯ������ָ��
    int i; // �������
    int nDepth; // ���ڽ��׵���ȣ�ȷ������
    bool fSpendable; // �Ƿ�ɻ���

    COutput(const CWalletTx *txIn, int iIn, int nDepthIn, bool fSpendableIn)
    {
        tx = txIn; i = iIn; nDepth = nDepthIn; fSpendable = fSpendableIn;
    }

    std::string ToString() const;
};




/** Private key that includes an expiration date in case it never gets used. */
class CWalletKey // ����һ�������޵�˽Կ�Է���˽Կ���ᱻʹ��
{
public:
    CPrivKey vchPrivKey; // ˽Կ
    int64_t nTimeCreated; // ����ʱ��
    int64_t nTimeExpires; // ����ʱ��
    std::string strComment; // ��ע
    //! todo: add something to note what created it (user, getnewaddress, change)
    //!   maybe should have a map<string, string> property map

    CWalletKey(int64_t nExpires=0);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPrivKey);
        READWRITE(nTimeCreated);
        READWRITE(nTimeExpires);
        READWRITE(LIMITED_STRING(strComment, 65536));
    }
};



/** 
 * A CWallet is an extension of a keystore, which also maintains a set of transactions and balances,
 * and provides the ability to create new transactions.
 */ // CWallet ����Կ�����չ������ά��һ�齻�׺������ṩ�����½��׵�������
class CWallet : public CCryptoKeyStore, public CValidationInterface
{
private:
    /**
     * Select a set of coins such that nValueRet >= nTargetValue and at least
     * all coins from coinControl are selected; Never select unconfirmed coins
     * if they are not ours
     */
    bool SelectCoins(const CAmount& nTargetValue, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet, const CCoinControl *coinControl = NULL) const;

    CWalletDB *pwalletdbEncryption; // Ǯ�����ݿ����ָ��

    //! the current wallet version: clients below this version are not able to load the wallet
    int nWalletVersion; // ��ǰ��Ǯ���汾���ͻ��˵��ڸð汾ʱ���ܼ���Ǯ��

    //! the maximum wallet format version: memory-only variable that specifies to what version this wallet may be upgraded
    int nWalletMaxVersion; // Ǯ��������ʽ�汾���ڴ��еı�����ָ��Ǯ�����������İ汾

    int64_t nNextResend;
    int64_t nLastResend;
    bool fBroadcastTransactions; // �㲥���׵ı�־

    /**
     * Used to keep track of spent outpoints, and
     * detect and report conflicts (double-spends or
     * mutated transactions where the mutant gets mined).
     */ // ���ڸ��ٻ�������㣬�����ͱ����ͻ��˫�� �� �ڿ�ͻ�䵼�µĿɱ�Ľ��ף�
    typedef std::multimap<COutPoint, uint256> TxSpends;
    TxSpends mapTxSpends; // ���׻���ӳ���б�
    void AddToSpends(const COutPoint& outpoint, const uint256& wtxid);
    void AddToSpends(const uint256& wtxid);

    /* Mark a transaction (and its in-wallet descendants) as conflicting with a particular block. */ // ���һ�ʽ��ף�������Ǯ���ڵ��ӽ��ף�Ϊ��һ��������ͻ
    void MarkConflicted(const uint256& hashBlock, const uint256& hashTx);

    void SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator>);

public:
    /*
     * Main wallet lock.
     * This lock protects all the fields added by CWallet
     *   except for:
     *      fFileBacked (immutable after instantiation)
     *      strWalletFile (immutable after instantiation)
     */
    mutable CCriticalSection cs_wallet; // ��Ǯ������������ CWallet ��������������Ա����ӵ�Ǯ����ȫ����Ա����

    bool fFileBacked; // �ļ��Ƿ��ѱ��ݵı�־
    std::string strWalletFile; // Ǯ���ļ����ļ���

    std::set<int64_t> setKeyPool; // ��Կ�ؼ��ϣ����ڼ�¼��Կ������������ 1 ��ʼ����
    std::map<CKeyID, CKeyMetadata> mapKeyMetadata; // ��ԿԪ����ӳ���б�

    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys; // ����Կӳ��
    unsigned int nMasterKeyMaxID; // ����Կ���������

    CWallet()
    {
        SetNull();
    }

    CWallet(const std::string& strWalletFileIn)
    {
        SetNull(); // ��ʼ��Ǯ��

        strWalletFile = strWalletFileIn; // ����Ǯ���ļ�
        fFileBacked = true; // �ļ����ݱ�־��Ϊ true
    }

    ~CWallet()
    {
        delete pwalletdbEncryption;
        pwalletdbEncryption = NULL;
    }

    void SetNull() // Ǯ�������ڴ��ʼ��
    {
        nWalletVersion = FEATURE_BASE;
        nWalletMaxVersion = FEATURE_BASE;
        fFileBacked = false;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = NULL;
        nOrderPosNext = 0;
        nNextResend = 0;
        nLastResend = 0;
        nTimeFirstKey = 0;
        fBroadcastTransactions = false;
    }

    std::map<uint256, CWalletTx> mapWallet; // Ǯ������ӳ���б� <���������� Ǯ������>
    std::list<CAccountingEntry> laccentries; // �˻���Ŀ�б�

    typedef std::pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap<int64_t, TxPair > TxItems;
    TxItems wtxOrdered; // ������ӳ���б�

    int64_t nOrderPosNext; // ��һ�����׵����
    std::map<uint256, int> mapRequestCount; // ��Ϣ����getdata������ӳ���б� <�����ϣ������>

    std::map<CTxDestination, CAddressBookData> mapAddressBook; // ��ַ��ӳ���б� <��ַ�� ��ַ������>

    CPubKey vchDefaultKey; // Ĭ�Ϲ�Կ

    std::set<COutPoint> setLockedCoins; // �����Ľ����������

    int64_t nTimeFirstKey; // �׸���Կ����ʱ�䣬����Ǯ���Ĵ���ʱ��

    const CWalletTx* GetWalletTx(const uint256& hash) const;

    //! check whether we are allowed to upgrade (or already support) to the named feature
    bool CanSupportFeature(enum WalletFeature wf) { AssertLockHeld(cs_wallet); return nWalletMaxVersion >= wf; } // ����Ƿ����Ǳ���������������֧�֣�����֪������

    /**
     * populate vCoins with vector of available COutputs.
     */
    void AvailableCoins(std::vector<COutput>& vCoins, bool fOnlyConfirmed=true, const CCoinControl *coinControl = NULL, bool fIncludeZeroValue=false) const;

    /**
     * Shuffle and select coins until nTargetValue is reached while avoiding
     * small change; This method is stochastic for some inputs and upon
     * completion the coin set and corresponding actual target value is
     * assembled
     */
    bool SelectCoinsMinConf(const CAmount& nTargetValue, int nConfMine, int nConfTheirs, std::vector<COutput> vCoins, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet) const;

    bool IsSpent(const uint256& hash, unsigned int n) const;

    bool IsLockedCoin(uint256 hash, unsigned int n) const;
    void LockCoin(COutPoint& output); // ����ָ���������
    void UnlockCoin(COutPoint& output); // ����ָ���������
    void UnlockAllCoins(); // ����ȫ���������
    void ListLockedCoins(std::vector<COutPoint>& vOutpts); // ��ȡ�����Ľ����������

    /**
     * keystore implementation
     * Generate a new key
     */ // ��Կ��
    CPubKey GenerateNewKey(); // ����һ������Կ
    //! Adds a key to the store, and saves it to disk.
    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey); // �����Կ��Ǯ���������ػ�������
    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key, const CPubKey &pubkey) { return CCryptoKeyStore::AddKeyPubKey(key, pubkey); } // ���һ����Կ��Ǯ���ڴ棬�����ػ������̣����� LoadWallet��
    //! Load metadata (used by LoadWallet)
    bool LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &metadata);

    bool LoadMinVersion(int nVersion) { AssertLockHeld(cs_wallet); nWalletVersion = nVersion; nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion); return true; }

    //! Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    //! Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    bool AddCScript(const CScript& redeemScript);
    bool LoadCScript(const CScript& redeemScript);

    //! Adds a destination data tuple to the store, and saves it to disk
    bool AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value);
    //! Erases a destination data tuple in the store and on disk
    bool EraseDestData(const CTxDestination &dest, const std::string &key);
    //! Adds a destination data tuple to the store, without saving it to disk
    bool LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value);
    //! Look up a destination data tuple in the store, return true if found false otherwise
    bool GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const;

    //! Adds a watch-only address to the store, and saves it to disk.
    bool AddWatchOnly(const CScript &dest);
    bool RemoveWatchOnly(const CScript &dest);
    //! Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)
    bool LoadWatchOnly(const CScript &dest);

    bool Unlock(const SecureString& strWalletPassphrase);
    bool ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase); // �ı�Ǯ������
    bool EncryptWallet(const SecureString& strWalletPassphrase); // ʹ���û�ָ���������Ǯ��

    void GetKeyBirthTimes(std::map<CKeyID, int64_t> &mapKeyBirth) const;

    /** 
     * Increment the next transaction order id
     * @return next transaction order id
     */ // ������һ��������ţ�������һ�����׵����
    int64_t IncOrderPosNext(CWalletDB *pwalletdb = NULL);

    void MarkDirty(); // ����ѱ䶯
    bool AddToWallet(const CWalletTx& wtxIn, bool fFromLoadWallet, CWalletDB* pwalletdb);
    void SyncTransaction(const CTransaction& tx, const CBlock* pblock);
    bool AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate);
    int ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false); // ��ָ�����鿪ʼɨ��Ǯ������
    void ReacceptWalletTransactions(); // �ٴν���Ǯ�����ף��ѽ��׷����ڴ��
    void ResendWalletTransactions(int64_t nBestBlockTime);
    std::vector<uint256> ResendWalletTransactionsBefore(int64_t nTime); // ���·���ĳʱ���ǰ��Ǯ������
    CAmount GetBalance() const; // ��ȡǮ�����
    CAmount GetUnconfirmedBalance() const; // ��ȡǮ����δȷ�ϵ����
    CAmount GetImmatureBalance() const;
    CAmount GetWatchOnlyBalance() const;
    CAmount GetUnconfirmedWatchOnlyBalance() const;
    CAmount GetImmatureWatchOnlyBalance() const;

    /**
     * Insert additional inputs into the transaction by
     * calling CreateTransaction();
     */ // ͨ������ CreateTransaction() �����������뵽�����У�
    bool FundTransaction(CMutableTransaction& tx, CAmount& nFeeRet, int& nChangePosRet, std::string& strFailReason, bool includeWatching);

    /**
     * Create a new transaction paying the recipients with a set of coins
     * selected by SelectCoins(); Also create the change output, when needed
     */ // ͨ�� SelectCoins() ɸѡ��һ�����һ��֧�����������½��ף�����ҪʱҲ�������������
    bool CreateTransaction(const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosRet,
                           std::string& strFailReason, const CCoinControl *coinControl = NULL, bool sign = true);
    bool CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey); // �ύ����

    bool AddAccountingEntry(const CAccountingEntry&, CWalletDB & pwalletdb); // ����˻���Ŀ��Ǯ�����ݿ�

    static CFeeRate minTxFee; // ��С���׷�
    static CFeeRate fallbackFee; // �������׷�
    /**
     * Estimate the minimum fee considering user set parameters
     * and the required fee
     */ // �����û����ò�����������ã�������ͽ��׷�
    static CAmount GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool);
    /**
     * Return the minimum required fee taking into account the
     * floating relay fee and user set minimum transaction fee
     */ // ���ǵ������м̷Ѻ��û����õ���ͽ��׷ѣ�����������ͽ��׷�
    static CAmount GetRequiredFee(unsigned int nTxBytes);

    bool NewKeyPool(); // ��Ǿ���Կ�ص���Կλ��ʹ�ã�������ȫ������Կ
    bool TopUpKeyPool(unsigned int kpSize = 0); // �������Կ��
    void ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool);
    void KeepKey(int64_t nIndex); // ����Կ�����Ƴ�ָ����������Կ
    void ReturnKey(int64_t nIndex);
    bool GetKeyFromPool(CPubKey &key); // ����Կ���л�ȡһ����Կ�Ĺ�Կ
    int64_t GetOldestKeyPoolTime();
    void GetAllReserveKeys(std::set<CKeyID>& setAddress) const; // ��ȡ��Կ����ȫ��Ԥ��������Կ

    std::set< std::set<CTxDestination> > GetAddressGroupings(); // ��ȡ��ַ���鼯��
    std::map<CTxDestination, CAmount> GetAddressBalances(); // ��ȡ��ַ���ӳ���б�

    std::set<CTxDestination> GetAccountAddresses(const std::string& strAccount) const; // ����ָ�����˻���ȡ������ĵ�ַ��

    isminetype IsMine(const CTxIn& txin) const; // ���������Ƿ����ڱ���Ǯ��
    CAmount GetDebit(const CTxIn& txin, const isminefilter& filter) const;
    isminetype IsMine(const CTxOut& txout) const; // ��������Ƿ����ڱ���Ǯ��
    CAmount GetCredit(const CTxOut& txout, const isminefilter& filter) const;
    bool IsChange(const CTxOut& txout) const;
    CAmount GetChange(const CTxOut& txout) const;
    bool IsMine(const CTransaction& tx) const;
    /** should probably be renamed to IsRelevantToMe */
    bool IsFromMe(const CTransaction& tx) const;
    CAmount GetDebit(const CTransaction& tx, const isminefilter& filter) const;
    CAmount GetCredit(const CTransaction& tx, const isminefilter& filter) const;
    CAmount GetChange(const CTransaction& tx) const;
    void SetBestChain(const CBlockLocator& loc); // ���������

    DBErrors LoadWallet(bool& fFirstRunRet); // ����Ǯ�����ڴ�
    DBErrors ZapWalletTx(std::vector<CWalletTx>& vWtx);

    bool SetAddressBook(const CTxDestination& address, const std::string& strName, const std::string& purpose); // ���õ�ַ������ַ�������˻�����ַ��;��

    bool DelAddressBook(const CTxDestination& address);

    void UpdatedTransaction(const uint256 &hashTx);

    void Inventory(const uint256 &hash) // ���ӿ�棨ָ������� getdata ���������
    {
        {
            LOCK(cs_wallet);
            std::map<uint256, int>::iterator mi = mapRequestCount.find(hash);
            if (mi != mapRequestCount.end())
                (*mi).second++;
        }
    }

    void GetScriptForMining(boost::shared_ptr<CReserveScript> &script);
    void ResetRequestCount(const uint256 &hash) // ���������ϣ��Ӧ�� getdata �������Ϊ 0
    {
        LOCK(cs_wallet);
        mapRequestCount[hash] = 0;
    };
    
    unsigned int GetKeyPoolSize() // ��ȡ��Կ�ش�С
    {
        AssertLockHeld(cs_wallet); // setKeyPool
        return setKeyPool.size(); // ������Կ���������ϵĴ�С
    }

    bool SetDefaultKey(const CPubKey &vchPubKey); // ����Ĭ����Կ

    //! signify that a particular wallet feature is now used. this may change nWalletVersion and nWalletMaxVersion if those are lower
    bool SetMinVersion(enum WalletFeature, CWalletDB* pwalletdbIn = NULL, bool fExplicit = false);

    //! change which version we're allowed to upgrade to (note that this does not immediately imply upgrading to that format)
    bool SetMaxVersion(int nVersion);

    //! get the current wallet format (the oldest client version guaranteed to understand this wallet)
    int GetVersion() { LOCK(cs_wallet); return nWalletVersion; }

    //! Get wallet transactions that conflict with given transaction (spend same outputs)
    std::set<uint256> GetConflicts(const uint256& txid) const;

    //! Flush wallet (bitdb flush) // ˢ��Ǯ�������ݿ�ˢ�£�
    void Flush(bool shutdown=false);

    //! Verify the wallet database and perform salvage if required // ��֤Ǯ�����ݿ⣬����Ҫ��ʵʩ���
    static bool Verify(const std::string& walletFile, std::string& warningString, std::string& errorString);
    
    /** 
     * Address book entry changed.
     * @note called with lock cs_wallet held.
     */ // ��ַ����Ŀ�ı䡣ע������ cs_wallet �����á�
    boost::signals2::signal<void (CWallet *wallet, const CTxDestination
            &address, const std::string &label, bool isMine,
            const std::string &purpose,
            ChangeType status)> NotifyAddressBookChanged;

    /** 
     * Wallet transaction added, removed or updated.
     * @note called with lock cs_wallet held.
     */ // Ǯ��������ӣ��Ƴ��͸���ʱ��
    boost::signals2::signal<void (CWallet *wallet, const uint256 &hashTx,
            ChangeType status)> NotifyTransactionChanged;

    /** Show progress e.g. for rescan */ // ��ʾ���ȣ����磺��ɨ��
    boost::signals2::signal<void (const std::string &title, int nProgress)> ShowProgress;

    /** Watch-only address added */ // ��� Watch-only ��ַ
    boost::signals2::signal<void (bool fHaveWatchOnly)> NotifyWatchonlyChanged;

    /** Inquire whether this wallet broadcasts transactions. */ // ��ѯ��Ǯ���Ƿ�㲥���ס�
    bool GetBroadcastTransactions() const { return fBroadcastTransactions; } // ���ع㲥���ױ�־
    /** Set whether this wallet broadcasts transactions. */ // ���ø�Ǯ���Ƿ�㲥���ס�
    void SetBroadcastTransactions(bool broadcast) { fBroadcastTransactions = broadcast; }

    /* Mark a transaction (and it in-wallet descendants) as abandoned so its inputs may be respent. */
    bool AbandonTransaction(const uint256& hashTx); // ���һ�ʽ��ף�����Ǯ�����ᣩΪ���������������������뱻���¹�ע
};

/** A key allocated from the key pool. */ // һ������Կ�ط������Կ��
class CReserveKey : public CReserveScript
{
protected:
    CWallet* pwallet; // Ǯ��ָ�룬ָ����Ǯ��
    int64_t nIndex; // ��Կ������Կ����������ʼ��Ϊ -1
    CPubKey vchPubKey; // ��Ӧ��Կ
public:
    CReserveKey(CWallet* pwalletIn)
    {
        nIndex = -1;
        pwallet = pwalletIn; // ��Ǯ��
    }

    ~CReserveKey()
    {
        ReturnKey();
    }

    void ReturnKey();
    bool GetReservedKey(CPubKey &pubkey); // ����Կ���л�ȡһ����Կ
    void KeepKey(); // ����Կ�����Ƴ���Կ����������ݳ�Ա vchPubKey
    void KeepScript() { KeepKey(); }
};


/** 
 * Account information.
 * Stored in wallet with key "acc"+string account name.
 */ // �˻���Ϣ���� "acc"+�˻��� Ϊ�ؼ��ִ洢��Ǯ���С�
class CAccount
{
public:
    CPubKey vchPubKey; // ��Կ

    CAccount()
    {
        SetNull();
    }

    void SetNull()
    {
        vchPubKey = CPubKey();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPubKey);
    }
};



/** 
 * Internal transfers.
 * Database key is acentry<account><counter>.
 */ // �ڲ�ת�ˡ����ݿ�ؼ�����<�˻�><������>��
class CAccountingEntry // �˻���Ŀ��
{
public:
    std::string strAccount; // �˻�������������룩
    CAmount nCreditDebit; // ���������
    int64_t nTime; // ת��ʱ�䣨ת�������ˣ�
    std::string strOtherAccount; // �Է��˻���
    std::string strComment; // ��ע��Ϣ
    mapValue_t mapValue;
    int64_t nOrderPos;  //! position in ordered transaction list // ���������嵥�е�λ��
    uint64_t nEntryNo;

    CAccountingEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        nCreditDebit = 0;
        nTime = 0;
        strAccount.clear();
        strOtherAccount.clear();
        strComment.clear();
        nOrderPos = -1;
        nEntryNo = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        //! Note: strAccount is serialized as part of the key, not here.
        READWRITE(nCreditDebit);
        READWRITE(nTime);
        READWRITE(LIMITED_STRING(strOtherAccount, 65536));

        if (!ser_action.ForRead())
        {
            WriteOrderPos(nOrderPos, mapValue);

            if (!(mapValue.empty() && _ssExtra.empty()))
            {
                CDataStream ss(nType, nVersion);
                ss.insert(ss.begin(), '\0');
                ss << mapValue;
                ss.insert(ss.end(), _ssExtra.begin(), _ssExtra.end());
                strComment.append(ss.str());
            }
        }

        READWRITE(LIMITED_STRING(strComment, 65536));

        size_t nSepPos = strComment.find("\0", 0, 1);
        if (ser_action.ForRead())
        {
            mapValue.clear();
            if (std::string::npos != nSepPos)
            {
                CDataStream ss(std::vector<char>(strComment.begin() + nSepPos + 1, strComment.end()), nType, nVersion);
                ss >> mapValue;
                _ssExtra = std::vector<char>(ss.begin(), ss.end());
            }
            ReadOrderPos(nOrderPos, mapValue);
        }
        if (std::string::npos != nSepPos)
            strComment.erase(nSepPos);

        mapValue.erase("n");
    }

private:
    std::vector<char> _ssExtra;
};

#endif // BITCOIN_WALLET_WALLET_H
