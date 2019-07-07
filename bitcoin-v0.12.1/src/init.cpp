// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "init.h"

#include "addrman.h"
#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "compat/sanity.h"
#include "consensus/validation.h"
#include "httpserver.h"
#include "httprpc.h"
#include "key.h"
#include "main.h"
#include "miner.h"
#include "net.h"
#include "policy/policy.h"
#include "rpcserver.h"
#include "script/standard.h"
#include "script/sigcache.h"
#include "scheduler.h"
#include "txdb.h"
#include "txmempool.h"
#include "torcontrol.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#ifdef ENABLE_WALLET
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif
#include <stdint.h>
#include <stdio.h>

#ifndef WIN32
#include <signal.h>
#endif

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/function.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>

#if ENABLE_ZMQ
#include "zmq/zmqnotificationinterface.h"
#endif

using namespace std;

#ifdef ENABLE_WALLET
CWallet* pwalletMain = NULL; // ָ����Ǯ�������ָ��
#endif
bool fFeeEstimatesInitialized = false;
static const bool DEFAULT_PROXYRANDOMIZE = true;
static const bool DEFAULT_REST_ENABLE = false;
static const bool DEFAULT_DISABLE_SAFEMODE = false;
static const bool DEFAULT_STOPAFTERBLOCKIMPORT = false;

#if ENABLE_ZMQ
static CZMQNotificationInterface* pzmqNotificationInterface = NULL;
#endif

#ifdef WIN32
// Win32 LevelDB doesn't use filedescriptors, and the ones used for
// accessing block files don't count towards the fd_set size limit
// anyway. // Win32 LevelDB ��ʹ���ļ������������ڷ��ʿ��ļ��Ĳ������ fd_set ��С���ơ�
#define MIN_CORE_FILEDESCRIPTORS 0 // Windows
#else
#define MIN_CORE_FILEDESCRIPTORS 150 // Unix/Linux
#endif

/** Used to pass flags to the Bind() function */ // ���� Bind() �����ı�־
enum BindFlags { // �󶨱�־ö��
    BF_NONE         = 0,
    BF_EXPLICIT     = (1U << 0),
    BF_REPORT_ERROR = (1U << 1),
    BF_WHITELIST    = (1U << 2),
};

static const char* FEE_ESTIMATES_FILENAME="fee_estimates.dat";
CClientUIInterface uiInterface; // Declared but not defined in ui_interface.h

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

//
// Thread management and startup/shutdown:
//
// The network-processing threads are all part of a thread group
// created by AppInit() or the Qt main() function.
//
// A clean exit happens when StartShutdown() or the SIGTERM
// signal handler sets fRequestShutdown, which triggers
// the DetectShutdownThread(), which interrupts the main thread group.
// DetectShutdownThread() then exits, which causes AppInit() to
// continue (it .joins the shutdown thread).
// Shutdown() is then
// called to clean up database connections, and stop other
// threads that should only be stopped after the main network-processing
// threads have exited.
//
// Note that if running -daemon the parent process returns from AppInit2
// before adding any threads to the threadGroup, so .join_all() returns
// immediately and the parent exits from main().
//
// Shutdown for Qt is very similar, only it uses a QTimer to detect
// fRequestShutdown getting set, and then does the normal Qt
// shutdown thing.
//

volatile bool fRequestShutdown = false; // ����رձ�־����ʼΪ false

void StartShutdown()
{
    fRequestShutdown = true; // ������رձ�־��Ϊ true
}
bool ShutdownRequested()
{
    return fRequestShutdown; // ���ص�ǰ������رձ�־
}

class CCoinsViewErrorCatcher : public CCoinsViewBacked
{
public:
    CCoinsViewErrorCatcher(CCoinsView* view) : CCoinsViewBacked(view) {}
    bool GetCoins(const uint256 &txid, CCoins &coins) const {
        try {
            return CCoinsViewBacked::GetCoins(txid, coins);
        } catch(const std::runtime_error& e) {
            uiInterface.ThreadSafeMessageBox(_("Error reading from database, shutting down."), "", CClientUIInterface::MSG_ERROR);
            LogPrintf("Error reading from database: %s\n", e.what());
            // Starting the shutdown sequence and returning false to the caller would be
            // interpreted as 'entry not found' (as opposed to unable to read data), and
            // could lead to invalid interpretation. Just exit immediately, as we can't
            // continue anyway, and all writes should be atomic.
            abort();
        }
    }
    // Writes do not need similar protection, as failure to write is handled by the caller. // д�벻��Ҫ���Ƶı�������Ϊ����ʧ�����ɵ����ߴ���ġ�
};

static CCoinsViewDB *pcoinsdbview = NULL;
static CCoinsViewErrorCatcher *pcoinscatcher = NULL;
static boost::scoped_ptr<ECCVerifyHandle> globalVerifyHandle; // ������ָ���� STL �� std::unique_ptr ����

void Interrupt(boost::thread_group& threadGroup)
{
    InterruptHTTPServer();
    InterruptHTTPRPC();
    InterruptRPC();
    InterruptREST();
    InterruptTorControl();
    threadGroup.interrupt_all();
}

void Shutdown()
{
    LogPrintf("%s: In progress...\n", __func__);
    static CCriticalSection cs_Shutdown; // �����ر����ٽ����
    TRY_LOCK(cs_Shutdown, lockShutdown); // ����
    if (!lockShutdown)
        return;

    /// Note: Shutdown() must be able to handle cases in which AppInit2() failed part of the way,
    /// for example if the data directory was found to be locked.
    /// Be sure that anything that writes files or flushes caches only does this if the respective
    /// module was initialized.
    RenameThread("bitcoin-shutoff"); // ���������رҹر��߳�
    mempool.AddTransactionsUpdated(1);

    StopHTTPRPC(); // �ر� HTTP RPC ����
    StopREST(); // �ر� REST
    StopRPC(); // �ر� RPC
    StopHTTPServer(); // �ر� HTTP ������
#ifdef ENABLE_WALLET
    if (pwalletMain) // ��Ǯ������
        pwalletMain->Flush(false); // ˢ��Ǯ�����ݿ��ر�
#endif
    GenerateBitcoins(false, 0, Params()); // �رտ��߳�
    StopNode(); // �رսڵ�
    StopTorControl(); // �ر����·��
    UnregisterNodeSignals(GetNodeSignals()); // ��ע������ע��Ľڵ��źź���

    if (fFeeEstimatesInitialized) // �����ù����ѳ�ʼ��
    {
        boost::filesystem::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME; // ·��ƴ�ӻ�ȡ���ù����ļ�·��
        CAutoFile est_fileout(fopen(est_path.string().c_str(), "wb"), SER_DISK, CLIENT_VERSION); // �򿪷��ù����ļ�
        if (!est_fileout.IsNull()) // ���ļ�������
            mempool.WriteFeeEstimates(est_fileout); // д�������ͽ��׷��ú�ȷ���������ȼ���ͳ������
        else
            LogPrintf("%s: Failed to write fee estimates to %s\n", __func__, est_path.string());
        fFeeEstimatesInitialized = false;
    }

    { // ͬ����״̬������
        LOCK(cs_main); // ����
        if (pcoinsTip != NULL) {
            FlushStateToDisk(); // ˢ������״̬������������
        }
        delete pcoinsTip;
        pcoinsTip = NULL;
        delete pcoinscatcher;
        pcoinscatcher = NULL;
        delete pcoinsdbview;
        pcoinsdbview = NULL;
        delete pblocktree; // ɾ�����������ݿ�
        pblocktree = NULL;
    }
#ifdef ENABLE_WALLET
    if (pwalletMain)
        pwalletMain->Flush(true); // ˢ��Ǯ��
#endif

#if ENABLE_ZMQ
    if (pzmqNotificationInterface) {
        UnregisterValidationInterface(pzmqNotificationInterface);
        delete pzmqNotificationInterface;
        pzmqNotificationInterface = NULL;
    }
#endif

#ifndef WIN32 // Unix/Linux
    try {
        boost::filesystem::remove(GetPidFile()); // ɾ�����̺��ļ�
    } catch (const boost::filesystem::filesystem_error& e) {
        LogPrintf("%s: Unable to remove pidfile: %s\n", __func__, e.what());
    }
#endif
    UnregisterAllValidationInterfaces(); // ��ע��������֤�ӿ�
#ifdef ENABLE_WALLET
    delete pwalletMain; // ɾ��Ǯ���Ѷ���
    pwalletMain = NULL; // ָ���ÿ�
#endif
    globalVerifyHandle.reset();
    ECC_Stop(); // �ر���Բ����
    LogPrintf("%s: done\n", __func__); // ��¼��־���ر����
}

/**
 * Signal handlers are very limited in what they are allowed to do, so:
 */ // �źŴ������������ķ�Χ�ڷǳ����ޣ���ˣ�
void HandleSIGTERM(int)
{
    fRequestShutdown = true;
}

void HandleSIGHUP(int)
{
    fReopenDebugLog = true;
}

bool static InitError(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, "", CClientUIInterface::MSG_ERROR); // ������Ϣ����ʾ�û�
    return false;
}

bool static InitWarning(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, "", CClientUIInterface::MSG_WARNING);
    return true;
}

bool static Bind(const CService &addr, unsigned int flags) { // �󶨲���ȡ״̬
    if (!(flags & BF_EXPLICIT) && IsLimited(addr))
        return false;
    std::string strError;
    if (!BindListenPort(addr, strError, (flags & BF_WHITELIST) != 0)) { // �󶨲������˿�
        if (flags & BF_REPORT_ERROR)
            return InitError(strError);
        return false;
    }
    return true; // �ɹ����� true
}

void OnRPCStopped()
{
    cvBlockChange.notify_all(); // ֪ͨ���еȴ����� cvBlockChange ���߳�
    LogPrint("rpc", "RPC stopped.\n"); // ��¼��־
}

void OnRPCPreCommand(const CRPCCommand& cmd)
{
    // Observe safe mode // ��ذ�ȫģʽ
    string strWarning = GetWarnings("rpc"); // ��ȡ rpc ������Ϣ
    if (strWarning != "" && !GetBoolArg("-disablesafemode", DEFAULT_DISABLE_SAFEMODE) &&
        !cmd.okSafeMode) // ���о�����Ϣ �� δ���ð�ȫģʽ �� RPC ����ǰ�ȫģʽ����
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, string("Safe mode: ") + strWarning); // �׳��쳣
}

std::string HelpMessage(HelpMessageMode mode)
{
    const bool showDebug = GetBoolArg("-help-debug", false); // ����ѡ�Ĭ�Ϲر�

    // When adding new options to the categories, please keep and ensure alphabetical ordering. // �������ѡ����ʱ����ȷ������ĸ˳������
    // Do not translate _(...) -help-debug options, Many technical terms, and only a very small audience, so is unnecessary stress to translators. // ��Ҫ����  _(...) -help-debug ѡ���༼�����ֻ�зǳ�С�����ڣ����Զ�������˵�ǲ���Ҫ��ѹ����
    string strUsage = HelpMessageGroup(_("Options:"));
    strUsage += HelpMessageOpt("-?", _("This help message"));
    strUsage += HelpMessageOpt("-version", _("Print version and exit"));
    strUsage += HelpMessageOpt("-alerts", strprintf(_("Receive and display P2P network alerts (default: %u)"), DEFAULT_ALERTS));
    strUsage += HelpMessageOpt("-alertnotify=<cmd>", _("Execute command when a relevant alert is received or we see a really long fork (%s in cmd is replaced by message)"));
    strUsage += HelpMessageOpt("-blocknotify=<cmd>", _("Execute command when the best block changes (%s in cmd is replaced by block hash)"));
    if (showDebug)
        strUsage += HelpMessageOpt("-blocksonly", strprintf(_("Whether to operate in a blocks only mode (default: %u)"), DEFAULT_BLOCKSONLY));
    strUsage += HelpMessageOpt("-checkblocks=<n>", strprintf(_("How many blocks to check at startup (default: %u, 0 = all)"), DEFAULT_CHECKBLOCKS));
    strUsage += HelpMessageOpt("-checklevel=<n>", strprintf(_("How thorough the block verification of -checkblocks is (0-4, default: %u)"), DEFAULT_CHECKLEVEL));
    strUsage += HelpMessageOpt("-conf=<file>", strprintf(_("Specify configuration file (default: %s)"), BITCOIN_CONF_FILENAME));
    if (mode == HMM_BITCOIND)
    {
#ifndef WIN32
        strUsage += HelpMessageOpt("-daemon", _("Run in the background as a daemon and accept commands"));
#endif
    }
    strUsage += HelpMessageOpt("-datadir=<dir>", _("Specify data directory"));
    strUsage += HelpMessageOpt("-dbcache=<n>", strprintf(_("Set database cache size in megabytes (%d to %d, default: %d)"), nMinDbCache, nMaxDbCache, nDefaultDbCache));
    strUsage += HelpMessageOpt("-loadblock=<file>", _("Imports blocks from external blk000??.dat file on startup"));
    strUsage += HelpMessageOpt("-maxorphantx=<n>", strprintf(_("Keep at most <n> unconnectable transactions in memory (default: %u)"), DEFAULT_MAX_ORPHAN_TRANSACTIONS));
    strUsage += HelpMessageOpt("-maxmempool=<n>", strprintf(_("Keep the transaction memory pool below <n> megabytes (default: %u)"), DEFAULT_MAX_MEMPOOL_SIZE));
    strUsage += HelpMessageOpt("-mempoolexpiry=<n>", strprintf(_("Do not keep transactions in the mempool longer than <n> hours (default: %u)"), DEFAULT_MEMPOOL_EXPIRY));
    strUsage += HelpMessageOpt("-par=<n>", strprintf(_("Set the number of script verification threads (%u to %d, 0 = auto, <0 = leave that many cores free, default: %d)"),
        -GetNumCores(), MAX_SCRIPTCHECK_THREADS, DEFAULT_SCRIPTCHECK_THREADS));
#ifndef WIN32
    strUsage += HelpMessageOpt("-pid=<file>", strprintf(_("Specify pid file (default: %s)"), BITCOIN_PID_FILENAME));
#endif
    strUsage += HelpMessageOpt("-prune=<n>", strprintf(_("Reduce storage requirements by pruning (deleting) old blocks. This mode is incompatible with -txindex and -rescan. "
            "Warning: Reverting this setting requires re-downloading the entire blockchain. "
            "(default: 0 = disable pruning blocks, >%u = target size in MiB to use for block files)"), MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
    strUsage += HelpMessageOpt("-reindex", _("Rebuild block chain index from current blk000??.dat files on startup"));
#ifndef WIN32
    strUsage += HelpMessageOpt("-sysperms", _("Create new files with system default permissions, instead of umask 077 (only effective with disabled wallet functionality)"));
#endif
    strUsage += HelpMessageOpt("-txindex", strprintf(_("Maintain a full transaction index, used by the getrawtransaction rpc call (default: %u)"), DEFAULT_TXINDEX));

    strUsage += HelpMessageGroup(_("Connection options:"));
    strUsage += HelpMessageOpt("-addnode=<ip>", _("Add a node to connect to and attempt to keep the connection open"));
    strUsage += HelpMessageOpt("-banscore=<n>", strprintf(_("Threshold for disconnecting misbehaving peers (default: %u)"), DEFAULT_BANSCORE_THRESHOLD));
    strUsage += HelpMessageOpt("-bantime=<n>", strprintf(_("Number of seconds to keep misbehaving peers from reconnecting (default: %u)"), DEFAULT_MISBEHAVING_BANTIME));
    strUsage += HelpMessageOpt("-bind=<addr>", _("Bind to given address and always listen on it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-connect=<ip>", _("Connect only to the specified node(s)"));
    strUsage += HelpMessageOpt("-discover", _("Discover own IP addresses (default: 1 when listening and no -externalip or -proxy)"));
    strUsage += HelpMessageOpt("-dns", _("Allow DNS lookups for -addnode, -seednode and -connect") + " " + strprintf(_("(default: %u)"), DEFAULT_NAME_LOOKUP));
    strUsage += HelpMessageOpt("-dnsseed", _("Query for peer addresses via DNS lookup, if low on addresses (default: 1 unless -connect)"));
    strUsage += HelpMessageOpt("-externalip=<ip>", _("Specify your own public address"));
    strUsage += HelpMessageOpt("-forcednsseed", strprintf(_("Always query for peer addresses via DNS lookup (default: %u)"), DEFAULT_FORCEDNSSEED));
    strUsage += HelpMessageOpt("-listen", _("Accept connections from outside (default: 1 if no -proxy or -connect)"));
    strUsage += HelpMessageOpt("-listenonion", strprintf(_("Automatically create Tor hidden service (default: %d)"), DEFAULT_LISTEN_ONION));
    strUsage += HelpMessageOpt("-maxconnections=<n>", strprintf(_("Maintain at most <n> connections to peers (default: %u)"), DEFAULT_MAX_PEER_CONNECTIONS));
    strUsage += HelpMessageOpt("-maxreceivebuffer=<n>", strprintf(_("Maximum per-connection receive buffer, <n>*1000 bytes (default: %u)"), DEFAULT_MAXRECEIVEBUFFER));
    strUsage += HelpMessageOpt("-maxsendbuffer=<n>", strprintf(_("Maximum per-connection send buffer, <n>*1000 bytes (default: %u)"), DEFAULT_MAXSENDBUFFER));
    strUsage += HelpMessageOpt("-onion=<ip:port>", strprintf(_("Use separate SOCKS5 proxy to reach peers via Tor hidden services (default: %s)"), "-proxy"));
    strUsage += HelpMessageOpt("-onlynet=<net>", _("Only connect to nodes in network <net> (ipv4, ipv6 or onion)"));
    strUsage += HelpMessageOpt("-permitbaremultisig", strprintf(_("Relay non-P2SH multisig (default: %u)"), DEFAULT_PERMIT_BAREMULTISIG));
    strUsage += HelpMessageOpt("-peerbloomfilters", strprintf(_("Support filtering of blocks and transaction with bloom filters (default: %u)"), 1));
    if (showDebug)
        strUsage += HelpMessageOpt("-enforcenodebloom", strprintf("Enforce minimum protocol version to limit use of bloom filters (default: %u)", 0));
    strUsage += HelpMessageOpt("-port=<port>", strprintf(_("Listen for connections on <port> (default: %u or testnet: %u)"), Params(CBaseChainParams::MAIN).GetDefaultPort(), Params(CBaseChainParams::TESTNET).GetDefaultPort()));
    strUsage += HelpMessageOpt("-proxy=<ip:port>", _("Connect through SOCKS5 proxy"));
    strUsage += HelpMessageOpt("-proxyrandomize", strprintf(_("Randomize credentials for every proxy connection. This enables Tor stream isolation (default: %u)"), DEFAULT_PROXYRANDOMIZE));
    strUsage += HelpMessageOpt("-seednode=<ip>", _("Connect to a node to retrieve peer addresses, and disconnect"));
    strUsage += HelpMessageOpt("-timeout=<n>", strprintf(_("Specify connection timeout in milliseconds (minimum: 1, default: %d)"), DEFAULT_CONNECT_TIMEOUT));
    strUsage += HelpMessageOpt("-torcontrol=<ip>:<port>", strprintf(_("Tor control port to use if onion listening enabled (default: %s)"), DEFAULT_TOR_CONTROL));
    strUsage += HelpMessageOpt("-torpassword=<pass>", _("Tor control port password (default: empty)"));
#ifdef USE_UPNP
#if USE_UPNP
    strUsage += HelpMessageOpt("-upnp", _("Use UPnP to map the listening port (default: 1 when listening and no -proxy)"));
#else
    strUsage += HelpMessageOpt("-upnp", strprintf(_("Use UPnP to map the listening port (default: %u)"), 0));
#endif
#endif
    strUsage += HelpMessageOpt("-whitebind=<addr>", _("Bind to given address and whitelist peers connecting to it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-whitelist=<netmask>", _("Whitelist peers connecting from the given netmask or IP address. Can be specified multiple times.") +
        " " + _("Whitelisted peers cannot be DoS banned and their transactions are always relayed, even if they are already in the mempool, useful e.g. for a gateway"));
    strUsage += HelpMessageOpt("-whitelistrelay", strprintf(_("Accept relayed transactions received from whitelisted peers even when not relaying transactions (default: %d)"), DEFAULT_WHITELISTRELAY));
    strUsage += HelpMessageOpt("-whitelistforcerelay", strprintf(_("Force relay of transactions from whitelisted peers even they violate local relay policy (default: %d)"), DEFAULT_WHITELISTFORCERELAY));
    strUsage += HelpMessageOpt("-maxuploadtarget=<n>", strprintf(_("Tries to keep outbound traffic under the given target (in MiB per 24h), 0 = no limit (default: %d)"), DEFAULT_MAX_UPLOAD_TARGET));

#ifdef ENABLE_WALLET
    strUsage += HelpMessageGroup(_("Wallet options:"));
    strUsage += HelpMessageOpt("-disablewallet", _("Do not load the wallet and disable wallet RPC calls"));
    strUsage += HelpMessageOpt("-keypool=<n>", strprintf(_("Set key pool size to <n> (default: %u)"), DEFAULT_KEYPOOL_SIZE));
    strUsage += HelpMessageOpt("-fallbackfee=<amt>", strprintf(_("A fee rate (in %s/kB) that will be used when fee estimation has insufficient data (default: %s)"),
        CURRENCY_UNIT, FormatMoney(DEFAULT_FALLBACK_FEE)));
    strUsage += HelpMessageOpt("-mintxfee=<amt>", strprintf(_("Fees (in %s/kB) smaller than this are considered zero fee for transaction creation (default: %s)"),
            CURRENCY_UNIT, FormatMoney(DEFAULT_TRANSACTION_MINFEE)));
    strUsage += HelpMessageOpt("-paytxfee=<amt>", strprintf(_("Fee (in %s/kB) to add to transactions you send (default: %s)"),
        CURRENCY_UNIT, FormatMoney(payTxFee.GetFeePerK())));
    strUsage += HelpMessageOpt("-rescan", _("Rescan the block chain for missing wallet transactions on startup"));
    strUsage += HelpMessageOpt("-salvagewallet", _("Attempt to recover private keys from a corrupt wallet.dat on startup"));
    strUsage += HelpMessageOpt("-sendfreetransactions", strprintf(_("Send transactions as zero-fee transactions if possible (default: %u)"), DEFAULT_SEND_FREE_TRANSACTIONS));
    strUsage += HelpMessageOpt("-spendzeroconfchange", strprintf(_("Spend unconfirmed change when sending transactions (default: %u)"), DEFAULT_SPEND_ZEROCONF_CHANGE));
    strUsage += HelpMessageOpt("-txconfirmtarget=<n>", strprintf(_("If paytxfee is not set, include enough fee so transactions begin confirmation on average within n blocks (default: %u)"), DEFAULT_TX_CONFIRM_TARGET));
    strUsage += HelpMessageOpt("-maxtxfee=<amt>", strprintf(_("Maximum total fees (in %s) to use in a single wallet transaction; setting this too low may abort large transactions (default: %s)"),
        CURRENCY_UNIT, FormatMoney(DEFAULT_TRANSACTION_MAXFEE)));
    strUsage += HelpMessageOpt("-upgradewallet", _("Upgrade wallet to latest format on startup"));
    strUsage += HelpMessageOpt("-wallet=<file>", _("Specify wallet file (within data directory)") + " " + strprintf(_("(default: %s)"), "wallet.dat"));
    strUsage += HelpMessageOpt("-walletbroadcast", _("Make the wallet broadcast transactions") + " " + strprintf(_("(default: %u)"), DEFAULT_WALLETBROADCAST));
    strUsage += HelpMessageOpt("-walletnotify=<cmd>", _("Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)"));
    strUsage += HelpMessageOpt("-zapwallettxes=<mode>", _("Delete all wallet transactions and only recover those parts of the blockchain through -rescan on startup") +
        " " + _("(1 = keep tx meta data e.g. account owner and payment request information, 2 = drop tx meta data)"));
#endif

#if ENABLE_ZMQ
    strUsage += HelpMessageGroup(_("ZeroMQ notification options:"));
    strUsage += HelpMessageOpt("-zmqpubhashblock=<address>", _("Enable publish hash block in <address>"));
    strUsage += HelpMessageOpt("-zmqpubhashtx=<address>", _("Enable publish hash transaction in <address>"));
    strUsage += HelpMessageOpt("-zmqpubrawblock=<address>", _("Enable publish raw block in <address>"));
    strUsage += HelpMessageOpt("-zmqpubrawtx=<address>", _("Enable publish raw transaction in <address>"));
#endif

    strUsage += HelpMessageGroup(_("Debugging/Testing options:"));
    strUsage += HelpMessageOpt("-uacomment=<cmt>", _("Append comment to the user agent string"));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-checkblockindex", strprintf("Do a full consistency check for mapBlockIndex, setBlockIndexCandidates, chainActive and mapBlocksUnlinked occasionally. Also sets -checkmempool (default: %u)", Params(CBaseChainParams::MAIN).DefaultConsistencyChecks()));
        strUsage += HelpMessageOpt("-checkmempool=<n>", strprintf("Run checks every <n> transactions (default: %u)", Params(CBaseChainParams::MAIN).DefaultConsistencyChecks()));
        strUsage += HelpMessageOpt("-checkpoints", strprintf("Disable expensive verification for known chain history (default: %u)", DEFAULT_CHECKPOINTS_ENABLED));
#ifdef ENABLE_WALLET
        strUsage += HelpMessageOpt("-dblogsize=<n>", strprintf("Flush wallet database activity from memory to disk log every <n> megabytes (default: %u)", DEFAULT_WALLET_DBLOGSIZE));
#endif
        strUsage += HelpMessageOpt("-disablesafemode", strprintf("Disable safemode, override a real safe mode event (default: %u)", DEFAULT_DISABLE_SAFEMODE));
        strUsage += HelpMessageOpt("-testsafemode", strprintf("Force safe mode (default: %u)", DEFAULT_TESTSAFEMODE));
        strUsage += HelpMessageOpt("-dropmessagestest=<n>", "Randomly drop 1 of every <n> network messages");
        strUsage += HelpMessageOpt("-fuzzmessagestest=<n>", "Randomly fuzz 1 of every <n> network messages");
#ifdef ENABLE_WALLET
        strUsage += HelpMessageOpt("-flushwallet", strprintf("Run a thread to flush wallet periodically (default: %u)", DEFAULT_FLUSHWALLET));
#endif
        strUsage += HelpMessageOpt("-stopafterblockimport", strprintf("Stop running after importing blocks from disk (default: %u)", DEFAULT_STOPAFTERBLOCKIMPORT));
        strUsage += HelpMessageOpt("-limitancestorcount=<n>", strprintf("Do not accept transactions if number of in-mempool ancestors is <n> or more (default: %u)", DEFAULT_ANCESTOR_LIMIT));
        strUsage += HelpMessageOpt("-limitancestorsize=<n>", strprintf("Do not accept transactions whose size with all in-mempool ancestors exceeds <n> kilobytes (default: %u)", DEFAULT_ANCESTOR_SIZE_LIMIT));
        strUsage += HelpMessageOpt("-limitdescendantcount=<n>", strprintf("Do not accept transactions if any ancestor would have <n> or more in-mempool descendants (default: %u)", DEFAULT_DESCENDANT_LIMIT));
        strUsage += HelpMessageOpt("-limitdescendantsize=<n>", strprintf("Do not accept transactions if any ancestor would have more than <n> kilobytes of in-mempool descendants (default: %u).", DEFAULT_DESCENDANT_SIZE_LIMIT));
    }
    string debugCategories = "addrman, alert, bench, coindb, db, lock, rand, rpc, selectcoins, mempool, mempoolrej, net, proxy, prune, http, libevent, tor, zmq"; // Don't translate these and qt below
    if (mode == HMM_BITCOIN_QT)
        debugCategories += ", qt";
    strUsage += HelpMessageOpt("-debug=<category>", strprintf(_("Output debugging information (default: %u, supplying <category> is optional)"), 0) + ". " +
        _("If <category> is not supplied or if <category> = 1, output all debugging information.") + _("<category> can be:") + " " + debugCategories + ".");
    if (showDebug)
        strUsage += HelpMessageOpt("-nodebug", "Turn off debugging messages, same as -debug=0");
    strUsage += HelpMessageOpt("-gen", strprintf(_("Generate coins (default: %u)"), DEFAULT_GENERATE));
    strUsage += HelpMessageOpt("-genproclimit=<n>", strprintf(_("Set the number of threads for coin generation if enabled (-1 = all cores, default: %d)"), DEFAULT_GENERATE_THREADS));
    strUsage += HelpMessageOpt("-help-debug", _("Show all debugging options (usage: --help -help-debug)"));
    strUsage += HelpMessageOpt("-logips", strprintf(_("Include IP addresses in debug output (default: %u)"), DEFAULT_LOGIPS));
    strUsage += HelpMessageOpt("-logtimestamps", strprintf(_("Prepend debug output with timestamp (default: %u)"), DEFAULT_LOGTIMESTAMPS));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-logtimemicros", strprintf("Add microsecond precision to debug timestamps (default: %u)", DEFAULT_LOGTIMEMICROS));
        strUsage += HelpMessageOpt("-mocktime=<n>", "Replace actual time with <n> seconds since epoch (default: 0)");
        strUsage += HelpMessageOpt("-limitfreerelay=<n>", strprintf("Continuously rate-limit free transactions to <n>*1000 bytes per minute (default: %u)", DEFAULT_LIMITFREERELAY));
        strUsage += HelpMessageOpt("-relaypriority", strprintf("Require high priority for relaying free or low-fee transactions (default: %u)", DEFAULT_RELAYPRIORITY));
        strUsage += HelpMessageOpt("-maxsigcachesize=<n>", strprintf("Limit size of signature cache to <n> MiB (default: %u)", DEFAULT_MAX_SIG_CACHE_SIZE));
    }
    strUsage += HelpMessageOpt("-minrelaytxfee=<amt>", strprintf(_("Fees (in %s/kB) smaller than this are considered zero fee for relaying, mining and transaction creation (default: %s)"),
        CURRENCY_UNIT, FormatMoney(DEFAULT_MIN_RELAY_TX_FEE)));
    strUsage += HelpMessageOpt("-printtoconsole", _("Send trace/debug info to console instead of debug.log file"));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-printpriority", strprintf("Log transaction priority and fee per kB when mining blocks (default: %u)", DEFAULT_PRINTPRIORITY));
#ifdef ENABLE_WALLET
        strUsage += HelpMessageOpt("-privdb", strprintf("Sets the DB_PRIVATE flag in the wallet db environment (default: %u)", DEFAULT_WALLET_PRIVDB));
#endif
    }
    strUsage += HelpMessageOpt("-shrinkdebugfile", _("Shrink debug.log file on client startup (default: 1 when no -debug)"));

    AppendParamsHelpMessages(strUsage, showDebug);

    strUsage += HelpMessageGroup(_("Node relay options:"));
    if (showDebug)
        strUsage += HelpMessageOpt("-acceptnonstdtxn", strprintf("Relay and mine \"non-standard\" transactions (%sdefault: %u)", "testnet/regtest only; ", !Params(CBaseChainParams::TESTNET).RequireStandard()));
    strUsage += HelpMessageOpt("-bytespersigop", strprintf(_("Minimum bytes per sigop in transactions we relay and mine (default: %u)"), DEFAULT_BYTES_PER_SIGOP));
    strUsage += HelpMessageOpt("-datacarrier", strprintf(_("Relay and mine data carrier transactions (default: %u)"), DEFAULT_ACCEPT_DATACARRIER));
    strUsage += HelpMessageOpt("-datacarriersize", strprintf(_("Maximum size of data in data carrier transactions we relay and mine (default: %u)"), MAX_OP_RETURN_RELAY));
    strUsage += HelpMessageOpt("-mempoolreplacement", strprintf(_("Enable transaction replacement in the memory pool (default: %u)"), DEFAULT_ENABLE_REPLACEMENT));

    strUsage += HelpMessageGroup(_("Block creation options:"));
    strUsage += HelpMessageOpt("-blockminsize=<n>", strprintf(_("Set minimum block size in bytes (default: %u)"), DEFAULT_BLOCK_MIN_SIZE));
    strUsage += HelpMessageOpt("-blockmaxsize=<n>", strprintf(_("Set maximum block size in bytes (default: %d)"), DEFAULT_BLOCK_MAX_SIZE));
    strUsage += HelpMessageOpt("-blockprioritysize=<n>", strprintf(_("Set maximum size of high-priority/low-fee transactions in bytes (default: %d)"), DEFAULT_BLOCK_PRIORITY_SIZE));
    if (showDebug)
        strUsage += HelpMessageOpt("-blockversion=<n>", "Override block version to test forking scenarios");

    strUsage += HelpMessageGroup(_("RPC server options:"));
    strUsage += HelpMessageOpt("-server", _("Accept command line and JSON-RPC commands"));
    strUsage += HelpMessageOpt("-rest", strprintf(_("Accept public REST requests (default: %u)"), DEFAULT_REST_ENABLE));
    strUsage += HelpMessageOpt("-rpcbind=<addr>", _("Bind to given address to listen for JSON-RPC connections. Use [host]:port notation for IPv6. This option can be specified multiple times (default: bind to all interfaces)"));
    strUsage += HelpMessageOpt("-rpccookiefile=<loc>", _("Location of the auth cookie (default: data dir)"));
    strUsage += HelpMessageOpt("-rpcuser=<user>", _("Username for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcpassword=<pw>", _("Password for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcauth=<userpw>", _("Username and hashed password for JSON-RPC connections. The field <userpw> comes in the format: <USERNAME>:<SALT>$<HASH>. A canonical python script is included in share/rpcuser. This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-rpcport=<port>", strprintf(_("Listen for JSON-RPC connections on <port> (default: %u or testnet: %u)"), BaseParams(CBaseChainParams::MAIN).RPCPort(), BaseParams(CBaseChainParams::TESTNET).RPCPort()));
    strUsage += HelpMessageOpt("-rpcallowip=<ip>", _("Allow JSON-RPC connections from specified source. Valid for <ip> are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24). This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-rpcthreads=<n>", strprintf(_("Set the number of threads to service RPC calls (default: %d)"), DEFAULT_HTTP_THREADS));
    if (showDebug) {
        strUsage += HelpMessageOpt("-rpcworkqueue=<n>", strprintf("Set the depth of the work queue to service RPC calls (default: %d)", DEFAULT_HTTP_WORKQUEUE));
        strUsage += HelpMessageOpt("-rpcservertimeout=<n>", strprintf("Timeout during HTTP requests (default: %d)", DEFAULT_HTTP_SERVER_TIMEOUT));
    }

    return strUsage; // �����÷��ַ���
}

std::string LicenseInfo() // ���֤��Ϣ
{
    // todo: remove urls from translations on next change // todo�����´θ���ʱ�ӷ������Ƴ� urls
    return FormatParagraph(strprintf(_("Copyright (C) 2009-%i The Bitcoin Core Developers"), COPYRIGHT_YEAR)) + "\n" +
           "\n" +
           FormatParagraph(_("This is experimental software.")) + "\n" +
           "\n" +
           FormatParagraph(_("Distributed under the MIT software license, see the accompanying file COPYING or <http://www.opensource.org/licenses/mit-license.php>.")) + "\n" +
           "\n" +
           FormatParagraph(_("This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit <https://www.openssl.org/> and cryptographic software written by Eric Young and UPnP software written by Thomas Bernard.")) +
           "\n"; // ���ظ�ʽ�����ı���Ϣ
}

static void BlockNotifyCallback(bool initialSync, const CBlockIndex *pBlockIndex)
{
    if (initialSync || !pBlockIndex)
        return;

    std::string strCmd = GetArg("-blocknotify", ""); // ��ȡָ��������

    boost::replace_all(strCmd, "%s", pBlockIndex->GetBlockHash().GetHex()); // �滻��������ϣ�� 16 ������ʽ
    boost::thread t(runCommand, strCmd); // thread runs free // ����������д��������߳�
}

struct CImportingNow
{
    CImportingNow() {
        assert(fImporting == false);
        fImporting = true;
    }

    ~CImportingNow() {
        assert(fImporting == true);
        fImporting = false;
    }
};


// If we're using -prune with -reindex, then delete block files that will be ignored by the
// reindex.  Since reindexing works by starting at block file 0 and looping until a blockfile
// is missing, do the same here to delete any later block files after a gap.  Also delete all
// rev files since they'll be rewritten by the reindex anyway.  This ensures that vinfoBlockFile
// is in sync with what's actually on disk by the time we start downloading, so that pruning
// works correctly. // �������ͬʱʹ�� -prune �� -reindex��Ȼ��ɾ���������������Ե������ļ�����Ϊ�������Ĺ���ԭ���Ǵ������ļ� 0 ��ʼѭ��֪��һ�������ļ���ʧ�������ڴ�ִ����ͬ�Ĳ�����ɾ����ʧ�ļ������������ļ���ͬʱɾ�����лָ��ļ�����Ϊ���ǽ�ͨ����������д����ȷ���������ļ������ǿ�ʼ����ʱʵ���ڴ����ϵ�����ͬ��������޼�����������
void CleanupBlockRevFiles() // ɾ��ĳ��ȱʧ����֮��������������ݣ���ǰ׺Ϊ rev ���ļ�
{
    using namespace boost::filesystem;
    map<string, path> mapBlockFiles; // <�����ļ�������?????��, �����ļ�·����path��>

    // Glob all blk?????.dat and rev?????.dat files from the blocks directory. // ������Ŀ¼ȫ������ͻָ������ļ���
    // Remove the rev files immediately and insert the blk file paths into an // �����Ƴ��ָ��ļ����������ļ�·��
    // ordered map keyed by block file index. // ����һ����Ϊ�����ļ�����������ӳ���б��С�
    LogPrintf("Removing unusable blk?????.dat and rev?????.dat files for -reindex with -prune\n");
    path blocksdir = GetDataDir() / "blocks"; // ƴ����������Ŀ¼
    for (directory_iterator it(blocksdir); it != directory_iterator(); it++) { // ��������Ŀ¼�µ��ļ���directory_iterator Ĭ�Ϲ��캯����ָ��Ŀ¼β����
        if (is_regular_file(*it) && // �������ͨ�ļ�����
            it->path().filename().string().length() == 12 && // �ļ����ĳ���Ϊ 12����
            it->path().filename().string().substr(8,4) == ".dat") // �� 4 ���ַ�Ϊ ".dat"
        { // �ļ�У�飨�����ļ������ļ���ʽ��
            if (it->path().filename().string().substr(0,3) == "blk") // ��Ϊ�����ļ�
                mapBlockFiles[it->path().filename().string().substr(3,5)] = it->path();  // �������ļ���������ļ�·����Բ���ȥ���ļ�ӳ���б���
            else if (it->path().filename().string().substr(0,3) == "rev") // ��Ϊ�ָ��ļ�
                remove(it->path()); // �Ƴ� rev �ļ�
        }
    }

    // Remove all block files that aren't part of a contiguous set starting at // ͨ��ά�ֵ����ļ�������
    // zero by walking the ordered map (keys are block file indices) by // ��������ӳ���б���Ϊ�����ļ�������
    // keeping a separate counter.  Once we hit a gap (or if 0 doesn't exist) // ɾ�����в����ڴ� 0 ��ʼ���������ļ�
    // start removing block files. // һ�����ǵִ��ϵ����飨�� 0 �����ڣ�����ʼɾ�������ļ���
    int nContigCounter = 0; // ���ȱʧ�� blk �ļ���ɾ��ȱʧ�� blk ������� blk �ļ�
    BOOST_FOREACH(const PAIRTYPE(string, path)& item, mapBlockFiles) {
        if (atoi(item.first) == nContigCounter) { // �� 0 ��ʼ
            nContigCounter++; // ���ļ��������������� 1
            continue; // �������ļ����Ƚ���һ���ļ�
        } // ����
        remove(item.second); // �Ӹ��ļ���ʼɾ���������е��ļ�
    }
}

void ThreadImport(std::vector<boost::filesystem::path> vImportFiles) // ���������̴߳�����
{
    const CChainParams& chainparams = Params(); // ��ȡ����������
    RenameThread("bitcoin-loadblk"); // ������Ϊ���������߳�
    // -reindex // ������ѡ��
    if (fReindex) {
        CImportingNow imp; // ����������󣬰ѵ����־��Ϊ true
        int nFile = 0; // �ļ���Ŵ� 0 ��ʼ
        while (true) { // ѭ����������
            CDiskBlockPos pos(nFile, 0); // ���������ļ�λ�ö���
            if (!boost::filesystem::exists(GetBlockPosFilename(pos, "blk"))) // �жϸ��ļ��Ƿ����
                break; // No block files left to reindex // ��û��ʣ�������ļ�������������������
            FILE *file = OpenBlockFile(pos, true); // �����ļ����ڣ����
            if (!file) // ���ļ���ʧ��
                break; // This error is logged in OpenBlockFile // ��¼������Ϣ����־
            LogPrintf("Reindexing block file blk%05u.dat...\n", (unsigned int)nFile);
            LoadExternalBlockFile(chainparams, file, &pos); // �����ⲿ�������ļ�
            nFile++; // �ļ��ż� 1
        }
        pblocktree->WriteReindexing(false); // д����������־
        fReindex = false; // ��������Ϊ false
        LogPrintf("Reindexing finished\n");
        // To avoid ending up in a situation without genesis block, re-try initializing (no-op if reindexing worked): // Ϊ������û�д������������½������ٴγ��Գ�ʼ�������������������ˣ����޲�������
        InitBlockIndex(chainparams); // ��ʼ�������������ݿ�
    }

    // hardcoded $DATADIR/bootstrap.dat // Ӳ����� $DATADIR/bootstrap.dat
    boost::filesystem::path pathBootstrap = GetDataDir() / "bootstrap.dat"; // ·��ƴ��
    if (boost::filesystem::exists(pathBootstrap)) { // �����ļ�����
        FILE *file = fopen(pathBootstrap.string().c_str(), "rb"); // �� 2 ����ֻ��ģʽ���ļ�
        if (file) {
            CImportingNow imp;
            boost::filesystem::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
            LogPrintf("Importing bootstrap.dat...\n");
            LoadExternalBlockFile(chainparams, file); // �����ⲿ�������ļ�
            RenameOver(pathBootstrap, pathBootstrapOld); // �������ļ������� .old ��׺
        } else {
            LogPrintf("Warning: Could not open bootstrap file %s\n", pathBootstrap.string());
        }
    }

    // -loadblock= // ��������ѡ��
    BOOST_FOREACH(const boost::filesystem::path& path, vImportFiles) { // ����������������ļ�·���б�
        FILE *file = fopen(path.string().c_str(), "rb"); // �Զ�����ֻ��ģʽ��
        if (file) {
            CImportingNow imp;
            LogPrintf("Importing blocks file %s...\n", path.string());
            LoadExternalBlockFile(chainparams, file); // �����ⲿ�����ļ����ڴ�
        } else {
            LogPrintf("Warning: Could not open blocks file %s\n", path.string());
        }
    }

    if (GetBoolArg("-stopafterblockimport", DEFAULT_STOPAFTERBLOCKIMPORT)) { // ���������ֹͣ
        LogPrintf("Stopping after block import\n");
        StartShutdown(); // �رտͻ���
    }
}

/** Sanity checks
 *  Ensure that Bitcoin is running in a usable environment with all
 *  necessary library support.
 */ // �����Լ�顣ȷ�����ر��ھ���ȫ���ر���֧�ֵĿ��û��������С�
bool InitSanityCheck(void)
{
    if(!ECC_InitSanityCheck()) { // 1.��Բ��������ѧ��ʼ�������Լ��
        InitError("Elliptic curve cryptography sanity check failure. Aborting.");
        return false;
    }
    if (!glibc_sanity_test() || !glibcxx_sanity_test()) // 2.glibc �� glibcxx �����Բ���
        return false;

    return true; // ���ͨ������ true
}

bool AppInitServers(boost::thread_group& threadGroup)
{
    RPCServer::OnStopped(&OnRPCStopped); // 1.����ֹͣ RPC �źź���
    RPCServer::OnPreCommand(&OnRPCPreCommand); // 2.���Ӽ�ذ�ȫģʽ�źź���
    if (!InitHTTPServer()) //3. ��ʼ�� HTTP ����
        return false;
    if (!StartRPC()) // 4.���� RPC Զ�̹��̵���
        return false;
    if (!StartHTTPRPC()) // 5.���� HTTP RPC������ע��� RPC ��������
        return false;
    if (GetBoolArg("-rest", DEFAULT_REST_ENABLE) && !StartREST()) // 6.���� REST ����Ĭ�Ϲر�
        return false;
    if (!StartHTTPServer()) // 7.���� HTTP ����
        return false;
    return true;
}

// Parameter interaction based on rules // ���ڹ���Ĳ�������
void InitParameterInteraction()
{
    // when specifying an explicit binding address, you want to listen on it // ��ָ����ʾ�󶨵ĵ�ַʱ��
    // even when -connect or -proxy is specified // ����ָ���� -connect �� -proxy ѡ���ҲҪ������
    if (mapArgs.count("-bind")) { // ������ָ����ַ
        if (SoftSetBoolArg("-listen", true)) // ͬʱ�����õ�ַ
            LogPrintf("%s: parameter interaction: -bind set -> setting -listen=1\n", __func__);
    }
    if (mapArgs.count("-whitebind")) { // ��������ͬ��
        if (SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -whitebind set -> setting -listen=1\n", __func__);
    }

    if (mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0) { // ��������ָ����ַ�Ľڵ�
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default // ��ֻ���ӿ��Žڵ�ʱ����ʹ�� DNS ���ӻ�Ĭ�ϼ���
        if (SoftSetBoolArg("-dnsseed", false)) // �ر� dnsseed
            LogPrintf("%s: parameter interaction: -connect set -> setting -dnsseed=0\n", __func__);
        if (SoftSetBoolArg("-listen", false)) // �ر� listen
            LogPrintf("%s: parameter interaction: -connect set -> setting -listen=0\n", __func__);
    }

    if (mapArgs.count("-proxy")) { // ��ʹ���˴���
        // to protect privacy, do not listen by default if a default proxy server is specified // ���ڱ�����˽�����ָ����Ĭ�ϵĴ������������ʹ��Ĭ�ϼ���
        if (SoftSetBoolArg("-listen", false)) // �رռ���
            LogPrintf("%s: parameter interaction: -proxy set -> setting -listen=0\n", __func__);
        // to protect privacy, do not use UPNP when a proxy is set. The user may still specify -listen=1 // Ϊ�˱�����˽���������˴���ʱ��ʹ�� UPNP���û�������ָ�� -listen=1 ���������أ�
        // to listen locally, so don't rely on this happening through -listen below. // ���Բ�Ҫͨ������� -listen ���������������
        if (SoftSetBoolArg("-upnp", false)) // �رն˿�ӳ��
            LogPrintf("%s: parameter interaction: -proxy set -> setting -upnp=0\n", __func__);
        // to protect privacy, do not discover addresses by default // ���ڱ�����˽����ʹ��Ĭ�ϵķ��ֵ�ַ
        if (SoftSetBoolArg("-discover", false)) // �رյ�ַ����
            LogPrintf("%s: parameter interaction: -proxy set -> setting -discover=0\n", __func__);
    }

    if (!GetBoolArg("-listen", DEFAULT_LISTEN)) { // ����ѡ�Ĭ�Ͽ���
        // do not map ports or try to retrieve public IP when not listening (pointless) // �ڲ�����ʱ��ӳ��˿ڻ��Լ������� IP
        if (SoftSetBoolArg("-upnp", false)) // �رն˿�ӳ��
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -upnp=0\n", __func__);
        if (SoftSetBoolArg("-discover", false)) // �رյ�ַ����
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -discover=0\n", __func__);
        if (SoftSetBoolArg("-listenonion", false)) // �ر����·��
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -listenonion=0\n", __func__);
    }

    if (mapArgs.count("-externalip")) { // ��ָ�����ⲿ ip
        // if an explicit public IP is specified, do not try to find others // ���ָ���˹��� IP���򲻳��Է������� IP
        if (SoftSetBoolArg("-discover", false)) // �رյ�ַ����
            LogPrintf("%s: parameter interaction: -externalip set -> setting -discover=0\n", __func__);
    }

    if (GetBoolArg("-salvagewallet", false)) { // ���ر��˻ظ�Ǯ��ѡ��
        // Rewrite just private keys: rescan to find transactions // ֻ��д˽Կ����ɨ�����ڷ��ֽ���
        if (SoftSetBoolArg("-rescan", true)) // ������ɨ��
            LogPrintf("%s: parameter interaction: -salvagewallet=1 -> setting -rescan=1\n", __func__);
    }

    // -zapwallettx implies a rescan // -zapwallettx ��ζ����ɨ��
    if (GetBoolArg("-zapwallettxes", false)) { // ���ر� zap Ǯ������ѡ��
        if (SoftSetBoolArg("-rescan", true)) // ������ɨ��ѡ��
            LogPrintf("%s: parameter interaction: -zapwallettxes=<mode> -> setting -rescan=1\n", __func__);
    }

    // disable walletbroadcast and whitelistrelay in blocksonly mode // �ڽ���Ĭ���йر�Ǯ���㲥�Ͱ������м�
    if (GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY)) { // ������ģʽ��Ĭ�Ϲرգ���������
        if (SoftSetBoolArg("-whitelistrelay", false)) // ��رհ������м�
            LogPrintf("%s: parameter interaction: -blocksonly=1 -> setting -whitelistrelay=0\n", __func__);
#ifdef ENABLE_WALLET
        if (SoftSetBoolArg("-walletbroadcast", false)) // ͬʱ�ر�Ǯ���㲥
            LogPrintf("%s: parameter interaction: -blocksonly=1 -> setting -walletbroadcast=0\n", __func__);
#endif
    }

    // Forcing relay from whitelisted hosts implies we will accept relays from them in the first place. // ǿ�ƴӰ������������м̱������ǽ������ǣ����ף����ڵ��׸�λ�ý����м̡�
    if (GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY)) { // ������ǿ���м̣�Ĭ�Ͽ���
        if (SoftSetBoolArg("-whitelistrelay", true)) // �����������м�ѡ��
            LogPrintf("%s: parameter interaction: -whitelistforcerelay=1 -> setting -whitelistrelay=1\n", __func__);
    }
}

void InitLogging()
{
    fPrintToConsole = GetBoolArg("-printtoconsole", false); // 1.��ӡ������̨��Ĭ�Ϲر�
    fLogTimestamps = GetBoolArg("-logtimestamps", DEFAULT_LOGTIMESTAMPS); // ��¼��־ʱ�����Ĭ�ϴ�
    fLogTimeMicros = GetBoolArg("-logtimemicros", DEFAULT_LOGTIMEMICROS); // ʱ���΢�룬Ĭ�Ϲر�
    fLogIPs = GetBoolArg("-logips", DEFAULT_LOGIPS); // ��¼ IPs��Ĭ�Ϲر�

    LogPrintf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"); // 2.n ������
    LogPrintf("Bitcoin version %s (%s)\n", FormatFullVersion(), CLIENT_DATE); // ��¼���رҿͻ��˰汾�ź͹���ʱ��
}

/** Initialize bitcoin.
 *  @pre Parameters should be parsed and config file should be read.
 */ // ��ʼ�����رҡ�ǰ�᣺����Ӧ�ñ������������ļ�Ӧ�ñ���ȡ��
bool AppInit2(boost::thread_group& threadGroup, CScheduler& scheduler) // [P]3.11.�����ʼ������ 12 ��
{
    // ********************************************************* Step 1: setup // ��ʼ�����绷�����ҽ��źŴ�����
#ifdef _MSC_VER // 1.���� log ���������Ϊ WARNING �� log ������ļ�
    // Turn off Microsoft heap dump noise // �ر�΢���ת����ʾ��
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400 // 2.�����ж���Ϣ
    // Disable confusing "helpful" text message on abort, Ctrl-C // ���� Ctrl-C ����ʱ���˵ġ��������ı���Ϣ
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable Data Execution Prevention (DEP) // 3.��������ִ�б�����DEP��
    // Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
    // A failure is non-critical and needs no further attention! // ʧ�ܲ���Ҫ������Ҫ���⣡
#ifndef PROCESS_DEP_ENABLE
    // We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7), // ���������ﶨ��������Ϊ GCCs winbase.h �������Ƶ� _WIN32_WINNT >= 0x0601 (Windows 7)��
    // which is not correct. Can be removed, when GCCs winbase.h is fixed! // ���Ǵ���ġ�GCCs winbase.h �޸�ʱ����ɾ��
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL (WINAPI *PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol = (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != NULL) setProcDEPPol(PROCESS_DEP_ENABLE);
#endif

    if (!SetupNetworking()) // 4.���� Windows �׽���
        return InitError("Initializing networking failed");

#ifndef WIN32 // 5.�� WIN32 ƽ̨�������ļ�Ȩ�޺�����ź�
    if (GetBoolArg("-sysperms", false)) { // ��������ϵͳ�ļ�Ȩ��
#ifdef ENABLE_WALLET // ��������Ǯ��
        if (!GetBoolArg("-disablewallet", false)) // ��δ�ر�Ǯ������
            return InitError("-sysperms is not allowed in combination with enabled wallet functionality");
#endif
    } else {
        umask(077); // ��������
    }

    // Clean shutdown on SIGTERM // �� SIGTERM �ź�����չر�
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Reopen debug.log on SIGHUP // �� SIGHUP �ź������´� debug.log �ļ�
    struct sigaction sa_hup;
    sa_hup.sa_handler = HandleSIGHUP;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);

    // Ignore SIGPIPE, otherwise it will bring the daemon down if the client closes unexpectedly
    signal(SIGPIPE, SIG_IGN); // ���� SIGPIPE �źţ���������ͻ����쳣�ر�����ʹ�ػ����̹ر�
#endif

    // ********************************************************* Step 2: parameter interactions // �����������ã��磺����ü� prune �뽻������ txindex �ĳ�ͻ��⡢�ļ����������Ƶļ��
    const CChainParams& chainparams = Params(); // 1.��ȡ��ǰ��������

    // also see: InitParameterInteraction()

    // if using block pruning, then disable txindex // 2.���ʹ�������޼�����Ҫ��ֹ��������
    if (GetArg("-prune", 0)) { // �޼�ģʽ�����ý�����������Ĭ�Ϲر�
        if (GetBoolArg("-txindex", DEFAULT_TXINDEX)) // �������������޼�ģʽ�����ݣ���Ĭ�Ϲر�
            return InitError(_("Prune mode is incompatible with -txindex.")); // �����ݵ�ԭ���޼�ģʽֻ��������ͷ����������������ǽ������� txid
#ifdef ENABLE_WALLET // ��������Ǯ��
        if (GetBoolArg("-rescan", false)) { // ��ɨ�裨�޼�ģʽ�²���ʹ�ã������ʹ�� -reindex �ٴ�������������������Ĭ�Ϲر�
            return InitError(_("Rescans are not possible in pruned mode. You will need to use -reindex which will download the whole blockchain again."));
        }
#endif
    }

    // Make sure enough file descriptors are available // 3.ȷ���㹻���ļ�����������
    int nBind = std::max((int)mapArgs.count("-bind") + (int)mapArgs.count("-whitebind"), 1); // bind ռ�õ��ļ�����������
    int nUserMaxConnections = GetArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS); // �����������Ĭ�� 125
    nMaxConnections = std::max(nUserMaxConnections, 0); // ��¼�����������Ĭ��Ϊ 125

    // Trim requested connection counts, to fit into system limitations // �޼������������������Ӧϵͳ����
    nMaxConnections = std::max(std::min(nMaxConnections, (int)(FD_SETSIZE - nBind - MIN_CORE_FILEDESCRIPTORS)), 0); // Linux ��һ������ͬʱ�򿪵��ļ�����������Ϊ 1024��ʹ�� ulimit -a/-n �鿴
    int nFD = RaiseFileDescriptorLimit(nMaxConnections + MIN_CORE_FILEDESCRIPTORS); // windows ��ֱ�ӷ��� 2048��linux �·��سɹ��������ֵ nMaxConnections + MIN_CORE_FILEDESCRIPTORS
    if (nFD < MIN_CORE_FILEDESCRIPTORS) // �����������������ܵ��� 0
        return InitError(_("Not enough file descriptors available."));
    nMaxConnections = std::min(nFD - MIN_CORE_FILEDESCRIPTORS, nMaxConnections); // ѡȡ����ǰ���С����

    if (nMaxConnections < nUserMaxConnections) // ����������� 125 �����������棬����������ϵͳ���Ƶ��µ���������
        InitWarning(strprintf(_("Reducing -maxconnections from %d to %d, because of system limitations."), nUserMaxConnections, nMaxConnections));

    // ********************************************************* Step 3: parameter-to-internal-flags // ����ת��Ϊ�ڲ����������ⲿ����������ת��Ϊ�����ڲ���״̬��bool �Ͳ�����������ѡ�

    fDebug = !mapMultiArgs["-debug"].empty(); // 1.���Կ��أ�Ĭ�Ϲر�
    // Special-case: if -debug=0/-nodebug is set, turn off debugging messages // ������������������ -debug=0/-nodebug���رյ�����Ϣ
    const vector<string>& categories = mapMultiArgs["-debug"]; // ��ȡ��������б�
    if (GetBoolArg("-nodebug", false) || find(categories.begin(), categories.end(), string("0")) != categories.end()) // ��δ���� -nodebug ѡ�� �� ������б����ҵ� "0" ֵ
        fDebug = false; // ���Ա�־��Ϊ false

    // Check for -debugnet // 2.��� -debugnet ѡ��
    if (GetBoolArg("-debugnet", false)) // -debugnet ������Ĭ�Ϲرգ����Ʋ�֧�ָĲ�����ʹ�� -debug=net
        InitWarning(_("Unsupported argument -debugnet ignored, use -debug=net."));
    // Check for -socks - as this is a privacy risk to continue, exit here // ��� -socks ѡ����Ϊһ��Ҫ������ȥ�����ط��գ��������˳�
    if (mapArgs.count("-socks")) // -socks �Ѳ���֧�֣���ֻ֧�� SOCKS5 proxies
        return InitError(_("Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only SOCKS5 proxies are supported."));
    // Check for -tor - as this is a privacy risk to continue, exit here // ��� -tor ѡ����Ϊһ��Ҫ������ȥ�����ط��գ��������˳�
    if (GetBoolArg("-tor", false)) // -tor ������һ�����ط��գ���ʹ�� -onion ����
        return InitError(_("Unsupported argument -tor found, use -onion."));

    if (GetBoolArg("-benchmark", false)) // -benchmark �����Ѳ�֧�֣�ʹ�� -debug=bench
        InitWarning(_("Unsupported argument -benchmark ignored, use -debug=bench."));

    if (GetBoolArg("-whitelistalwaysrelay", false)) // -whitelistalwaysrelay ��������֧�֣�ʹ�� -whitelistrelay �� -whitelistforcerelay
        InitWarning(_("Unsupported argument -whitelistalwaysrelay ignored, use -whitelistrelay and/or -whitelistforcerelay."));

    // Checkmempool and checkblockindex default to true in regtest mode // 3.����ڴ�غͼ����������ѡ���ڻع����ģʽ��Ĭ��Ϊ true
    int ratio = std::min<int>(std::max<int>(GetArg("-checkmempool", chainparams.DefaultConsistencyChecks() ? 1 : 0), 0), 1000000); // 1 or 0 ��Ӧ true or false������Ĭ�Ϲر�
    if (ratio != 0) { // true
        mempool.setSanityCheck(1.0 / ratio); // �����ڴ�����������Լ��Ƶ��
    }
    fCheckBlockIndex = GetBoolArg("-checkblockindex", chainparams.DefaultConsistencyChecks()); // �������������־��Ĭ�ϣ��������������رգ��ع��������
    fCheckpointsEnabled = GetBoolArg("-checkpoints", DEFAULT_CHECKPOINTS_ENABLED); // ������ã�Ĭ�ϴ�

    // mempool limits // �����ڴ������ѡ��
    int64_t nMempoolSizeMax = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000; // �ڴ�ش�С���ƣ�Ĭ�Ͻӽ� 300M
    int64_t nMempoolSizeMin = GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000 * 40;
    if (nMempoolSizeMax < 0 || nMempoolSizeMax < nMempoolSizeMin)
        return InitError(strprintf(_("-maxmempool must be at least %d MB"), std::ceil(nMempoolSizeMin / 1000000.0)));

    // -par=0 means autodetect, but nScriptCheckThreads==0 means no concurrency // 4.-par=0 ��ζ���Զ���⣬�� nScriptCheckThreads==0 ��ζ��û�в���
    nScriptCheckThreads = GetArg("-par", DEFAULT_SCRIPTCHECK_THREADS); // �ű�����߳�����Ĭ��Ϊ 0
    if (nScriptCheckThreads <= 0)
        nScriptCheckThreads += GetNumCores(); // ÿ����һ���ű�����̣߳�Ĭ��
    if (nScriptCheckThreads <= 1)
        nScriptCheckThreads = 0;
    else if (nScriptCheckThreads > MAX_SCRIPTCHECK_THREADS)
        nScriptCheckThreads = MAX_SCRIPTCHECK_THREADS; // ����߳���Ϊ 16

    fServer = GetBoolArg("-server", false); // 5.����ѡ�3.8.������Ϊ true

    // block pruning; get the amount of disk space (in MiB) to allot for block & undo files // 6.�����޼�����ȡ���̿ռ������� MiB Ϊ��λ���Է�������ͳ����ļ������ڻָ���״̬�ķ��򲹶���
    int64_t nSignedPruneTarget = GetArg("-prune", 0) * 1024 * 1024; // 0 ��ʾ��ֹ�޼�����
    if (nSignedPruneTarget < 0) {
        return InitError(_("Prune cannot be configured with a negative value."));
    }
    nPruneTarget = (uint64_t) nSignedPruneTarget; // 0 ����� 0
    if (nPruneTarget) { // 0 ��ʾ��ֹ������ 0 ��ʾ�����޼�ģʽ
        if (nPruneTarget < MIN_DISK_SPACE_FOR_BLOCK_FILES) { // �޼���Ŀ����ڵ��� 550 MB��Ϊʲô��
            return InitError(strprintf(_("Prune configured below the minimum of %d MiB.  Please use a higher number."), MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
        }
        LogPrintf("Prune configured to target %uMiB on disk for block and undo files.\n", nPruneTarget / 1024 / 1024);
        fPruneMode = true;
    }

#ifdef ENABLE_WALLET
    bool fDisableWallet = GetBoolArg("-disablewallet", false); // 7.����Ǯ��ѡ�Ĭ�Ϲر�
#endif

    nConnectTimeout = GetArg("-timeout", DEFAULT_CONNECT_TIMEOUT); // 8.���ӳ�ʱ��Ĭ�� 5000
    if (nConnectTimeout <= 0)
        nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;

    // Fee-per-kilobyte amount considered the same as "free" // 9.ÿǧ�ֽڵĽ��׷ѱ���Ϊ�롰��ѡ���ͬ
    // If you are mining, be careful setting this: // ����������ڿ�С�����ø�ѡ�
    // if you set it to zero then // ��������ø�ֵΪ 0
    // a transaction spammer can cheaply fill blocks using // һ���۳����׷����߿�������ʹ�� 1 satoshi ���׷ѵĽ��������顣
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction. // ��ֵӦ������Ϊ�����׵ĳɱ�֮�ϡ�
    if (mapArgs.count("-minrelaytxfee")) // ����м̽��׷�ѡ��
    {
        CAmount n = 0;
        if (ParseMoney(mapArgs["-minrelaytxfee"], n) && n > 0)
            ::minRelayTxFee = CFeeRate(n);
        else
            return InitError(strprintf(_("Invalid amount for -minrelaytxfee=<amount>: '%s'"), mapArgs["-minrelaytxfee"]));
    }

    fRequireStandard = !GetBoolArg("-acceptnonstdtxn", !Params().RequireStandard());
    if (Params().RequireStandard() && !fRequireStandard)
        return InitError(strprintf("acceptnonstdtxn is not currently supported for %s chain", chainparams.NetworkIDString()));
    nBytesPerSigOp = GetArg("-bytespersigop", nBytesPerSigOp);

#ifdef ENABLE_WALLET
    if (mapArgs.count("-mintxfee")) // ��ͽ��׷�ѡ��
    {
        CAmount n = 0;
        if (ParseMoney(mapArgs["-mintxfee"], n) && n > 0)
            CWallet::minTxFee = CFeeRate(n);
        else
            return InitError(strprintf(_("Invalid amount for -mintxfee=<amount>: '%s'"), mapArgs["-mintxfee"]));
    }
    if (mapArgs.count("-fallbackfee"))
    {
        CAmount nFeePerK = 0;
        if (!ParseMoney(mapArgs["-fallbackfee"], nFeePerK))
            return InitError(strprintf(_("Invalid amount for -fallbackfee=<amount>: '%s'"), mapArgs["-fallbackfee"]));
        if (nFeePerK > nHighTransactionFeeWarning)
            InitWarning(_("-fallbackfee is set very high! This is the transaction fee you may pay when fee estimates are not available."));
        CWallet::fallbackFee = CFeeRate(nFeePerK);
    }
    if (mapArgs.count("-paytxfee")) // ���׷�ѡ��
    {
        CAmount nFeePerK = 0;
        if (!ParseMoney(mapArgs["-paytxfee"], nFeePerK))
            return InitError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s'"), mapArgs["-paytxfee"]));
        if (nFeePerK > nHighTransactionFeeWarning)
            InitWarning(_("-paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."));
        payTxFee = CFeeRate(nFeePerK, 1000);
        if (payTxFee < ::minRelayTxFee)
        {
            return InitError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s' (must be at least %s)"),
                                       mapArgs["-paytxfee"], ::minRelayTxFee.ToString()));
        }
    }
    if (mapArgs.count("-maxtxfee")) // ��߽��׷�ѡ��
    {
        CAmount nMaxFee = 0;
        if (!ParseMoney(mapArgs["-maxtxfee"], nMaxFee))
            return InitError(strprintf(_("Invalid amount for -maxtxfee=<amount>: '%s'"), mapArgs["-maxtxfee"]));
        if (nMaxFee > nHighTransactionMaxFeeWarning)
            InitWarning(_("-maxtxfee is set very high! Fees this large could be paid on a single transaction."));
        maxTxFee = nMaxFee;
        if (CFeeRate(maxTxFee, 1000) < ::minRelayTxFee)
        {
            return InitError(strprintf(_("Invalid amount for -maxtxfee=<amount>: '%s' (must be at least the minrelay fee of %s to prevent stuck transactions)"),
                                       mapArgs["-maxtxfee"], ::minRelayTxFee.ToString()));
        }
    }
    nTxConfirmTarget = GetArg("-txconfirmtarget", DEFAULT_TX_CONFIRM_TARGET);
    bSpendZeroConfChange = GetBoolArg("-spendzeroconfchange", DEFAULT_SPEND_ZEROCONF_CHANGE);
    fSendFreeTransactions = GetBoolArg("-sendfreetransactions", DEFAULT_SEND_FREE_TRANSACTIONS);

    std::string strWalletFile = GetArg("-wallet", "wallet.dat"); // ָ����Ǯ���ļ�����Ĭ��Ϊ "wallet.dat"
#endif // ENABLE_WALLET

    fIsBareMultisigStd = GetBoolArg("-permitbaremultisig", DEFAULT_PERMIT_BAREMULTISIG);
    fAcceptDatacarrier = GetBoolArg("-datacarrier", DEFAULT_ACCEPT_DATACARRIER);
    nMaxDatacarrierBytes = GetArg("-datacarriersize", nMaxDatacarrierBytes);

    fAlerts = GetBoolArg("-alerts", DEFAULT_ALERTS); // ת��ѡ�Ĭ�Ϲر�

    // Option to startup with mocktime set (used for regression testing): // ѡ��ʹ�� mocktime �������������ڻع���ԣ���
    SetMockTime(GetArg("-mocktime", 0)); // SetMockTime(0) is a no-op // SetMockTime(0) ��ʾ�޲���

    if (GetBoolArg("-peerbloomfilters", true))
        nLocalServices |= NODE_BLOOM;

    fEnableReplacement = GetBoolArg("-mempoolreplacement", DEFAULT_ENABLE_REPLACEMENT);
    if ((!fEnableReplacement) && mapArgs.count("-mempoolreplacement")) {
        // Minimal effort at forwards compatibility // ��ǰ�����Ե���СŬ��
        std::string strReplacementModeList = GetArg("-mempoolreplacement", "");  // default is impossible // Ĭ���ǲ�����
        std::vector<std::string> vstrReplacementModes;
        boost::split(vstrReplacementModes, strReplacementModeList, boost::is_any_of(","));
        fEnableReplacement = (std::find(vstrReplacementModes.begin(), vstrReplacementModes.end(), "fee") != vstrReplacementModes.end());
    }

    // ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log // ��ʼ�� ECC��Ŀ¼����飨��ֻ֤��һ�� bitcoind ���У���pid �ļ���debug ��־

    // Initialize elliptic curve code // 1.��ʼ����Բ���ߴ���
    ECC_Start(); // ��Բ���߱�������
    globalVerifyHandle.reset(new ECCVerifyHandle()); // ������Բ������֤����

    // Sanity check // 2.�����Լ��
    if (!InitSanityCheck()) // ��ʼ�������Լ�� pending
        return InitError(_("Initialization sanity check failed. Bitcoin Core is shutting down."));

    std::string strDataDir = GetDataDir().string(); // 3.1.��ȡ����Ŀ¼·��
#ifdef ENABLE_WALLET // ������Ǯ������
    // Wallet file must be a plain filename without a directory // 3.2.Ǯ���ļ������ǲ���Ŀ¼���ļ���
    if (strWalletFile != boost::filesystem::basename(strWalletFile) + boost::filesystem::extension(strWalletFile)) // ��֤Ǯ���ļ����������ԣ�basename ��ȡ�ļ������� "wallet"��extension ��ȡ�ļ���չ�� ".dat"
        return InitError(strprintf(_("Wallet %s resides outside data directory %s"), strWalletFile, strDataDir));
#endif // Ǯ����У�����
    // Make sure only a single Bitcoin process is using the data directory. // 3.3.ȷ��ֻ��һ�����رҽ���ʹ�ø�����Ŀ¼��
    boost::filesystem::path pathLockFile = GetDataDir() / ".lock"; // �յ� lock �����ļ������ã���Ϊ�ٽ���Դ����֤��ǰֻ��һ�� Bitcoin ����ʹ������Ŀ¼
    FILE* file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file) fclose(file); // ���ļ���������رոÿ��ļ�

    try {
        static boost::interprocess::file_lock lock(pathLockFile.string().c_str()); // ��ʼ���ļ�������
        if (!lock.try_lock()) // ����
            return InitError(strprintf(_("Cannot obtain a lock on data directory %s. Bitcoin Core is probably already running."), strDataDir)); // �ڶ������̻�����������ʧ�ܲ��˳�
    } catch(const boost::interprocess::interprocess_exception& e) {
        return InitError(strprintf(_("Cannot obtain a lock on data directory %s. Bitcoin Core is probably already running.") + " %s.", strDataDir, e.what()));
    }

#ifndef WIN32
    CreatePidFile(GetPidFile(), getpid()); // 4.�� win32 �����£����� pid �ļ�����¼��ǰ bitcoind �Ľ��̺ţ�
#endif
    if (GetBoolArg("-shrinkdebugfile", !fDebug)) // 5.�����������ļ�ѡ���
        ShrinkDebugFile(); // 5.1.����������־�ļ�

    if (fPrintToDebugLog) // ��ӡ��������־��־��Ĭ�ϴ�
        OpenDebugLog(); // 5.2.�򿪵�����־�ļ�

#ifdef ENABLE_WALLET
    LogPrintf("Using BerkeleyDB version %s\n", DbEnv::version(0, 0, 0)); // 6.Ǯ��ʹ�� BerkeleyDB
#endif
    if (!fLogTimestamps) // ʱ�����־��Ĭ�Ͽ���
        LogPrintf("Startup time: %s\n", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime())); // ��¼����ʱ��
    LogPrintf("Default data directory %s\n", GetDefaultDataDir().string()); // ��¼Ĭ������Ŀ¼
    LogPrintf("Using data directory %s\n", strDataDir); // ��¼��ǰָ��ʹ�õ�����Ŀ¼
    LogPrintf("Using config file %s\n", GetConfigFile().string()); // ��¼ʹ�õ������ļ�
    LogPrintf("Using at most %i connections (%i file descriptors available)\n", nMaxConnections, nFD); // ��¼��������������õ��ļ�������������
    std::ostringstream strErrors; // ������Ϣ���ַ��������

    LogPrintf("Using %u threads for script verification\n", nScriptCheckThreads); // ��¼�ű���֤�߳�����Ĭ��Ϊ CPU ������
    if (nScriptCheckThreads) { // 7.���� N-1 ���ű���֤�߳�
        for (int i=0; i<nScriptCheckThreads-1; i++)
            threadGroup.create_thread(&ThreadScriptCheck); // CCheckQueue ���е� loop ��Ա����
    }

    // Start the lightweight task scheduler thread // 8.������������������߳�
    CScheduler::Function serviceLoop = boost::bind(&CScheduler::serviceQueue, &scheduler); // 8.1.Function/bind �����Ա���� serviceQueue ���������� serviceLoop
    threadGroup.create_thread(boost::bind(&TraceThread<CScheduler::Function>, "scheduler", serviceLoop)); // 8.2.�߳��� threadGroup ����һ����������������߳�

    /* Start the RPC server already.  It will be started in "warmup" mode
     * and not really process calls already (but it will signify connections
     * that the server is there and will be ready later).  Warmup mode will
     * be disabled when initialisation is finished.
     */ // 9.�Ѿ����� RPC ���񡣽��ԡ�Ԥ�ȡ�ģʽ�����������Ѿ������ؿ�ʼ������ã�������ʾ�����������Ӳ���֮��׼���ã�����ʼ����ɺ�Ԥ��ģʽ�����رա�
    if (fServer) // �����־��Ĭ�ϴ򿪣�-server ѡ�Ϊ -cli �ṩ����
    {
        uiInterface.InitMessage.connect(SetRPCWarmupStatus); // 9.1.ע��/���� ���� RPC Ԥ��״̬����
        if (!AppInitServers(threadGroup)) // 9.2.Ӧ�ó����ʼ���������� HTTP��RPC ��ط���
            return InitError(_("Unable to start HTTP server. See debug log for details."));
    }

    int64_t nStart; // ������־

    // ********************************************************* Step 5: verify wallet database integrity // ��֤Ǯ�����ݿ��������
#ifdef ENABLE_WALLET // ǰ�ᣬENABLE_WALLET �� bitcoin-config.h �ж��壬ͨ�� ./configure --disable-wallet ������Ǯ��
    if (!fDisableWallet) { // ��ֹǮ����־��Ĭ�Ϲرգ���Ĭ�ϴ�Ǯ������
        LogPrintf("Using wallet %s\n", strWalletFile); // ��¼Ǯ���ļ�����ָ��/Ĭ�ϣ�
        uiInterface.InitMessage(_("Verifying wallet...")); // UI ��������ʼ��Ǯ����Ϣ

        std::string warningString; // ������Ϣ
        std::string errorString; // ������Ϣ

        if (!CWallet::Verify(strWalletFile, warningString, errorString)) // ��֤Ǯ�����ݿ�
            return false;

        if (!warningString.empty()) // ������Ϣ�ǿ�
            InitWarning(warningString);
        if (!errorString.empty()) // ������Ϣ�ǿ�
            return InitError(errorString);

    } // (!fDisableWallet)
#endif // ENABLE_WALLET
    // ********************************************************* Step 6: network initialization // �����ʼ��

    RegisterNodeSignals(GetNodeSignals()); // 1.ע��ڵ��źţ���ȡ�ڵ��ź�ȫ�ֶ��󣬴������ע��

    // sanitize comments per BIP-0014, format user agent and check total size // ���� BIP-0014 �������ۣ���ʽ���û���������ܴ�С
    std::vector<string> uacomments; // 2.����û����������б�
    BOOST_FOREACH(string cmt, mapMultiArgs["-uacomment"]) // ���α�����������
    {
        if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT)) // ���л��ַ�������бȽϣ���֤��������ȫ���ַ�
            return InitError(strprintf(_("User Agent comment (%s) contains unsafe characters."), cmt));
        uacomments.push_back(SanitizeString(cmt, SAFE_CHARS_UA_COMMENT)); // ���������б�
    }
    strSubVersion = FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments); // 6.3.��ȡ�ͻ��Ӱ汾��Ϣ
    if (strSubVersion.size() > MAX_SUBVERSION_LENGTH) { // �汾��Ϣ���ó��� 256 ���ֽ�
        return InitError(strprintf(_("Total length of network version string (%i) exceeds maximum length (%i). Reduce the number or size of uacomments."),
            strSubVersion.size(), MAX_SUBVERSION_LENGTH));
    }

    if (mapArgs.count("-onlynet")) { // 3.ָ������ѡ�ֻ���ӵ�ָ�������еĽڵ�
        std::set<enum Network> nets; // ���ָ������ļ���
        BOOST_FOREACH(const std::string& snet, mapMultiArgs["-onlynet"]) { // ���� -onlynet ������ֵ
            enum Network net = ParseNetwork(snet); // ��������
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet));
            nets.insert(net); // ����ָ������ļ���
        }
        for (int n = 0; n < NET_MAX; n++) { // �����������ͣ��� 5 ��
            enum Network net = (enum Network)n;
            if (!nets.count(net)) // ������������δָ��
                SetLimited(net); // ����δָ������������
        }
    }

    if (mapArgs.count("-whitelist")) { // 4.������ѡ��
        BOOST_FOREACH(const std::string& net, mapMultiArgs["-whitelist"]) { // ����ָ���İ������б�
            CSubNet subnet(net); // ������������
            if (!subnet.IsValid()) // ��������Ƿ���Ч
                return InitError(strprintf(_("Invalid netmask specified in -whitelist: '%s'"), net));
            CNode::AddWhitelistedRange(subnet); // ����Ч����������������б�
        }
    }

    bool proxyRandomize = GetBoolArg("-proxyrandomize", DEFAULT_PROXYRANDOMIZE); // 5.���������ѡ�Ĭ�Ͽ���
    // -proxy sets a proxy for all outgoing network traffic // -proxy ����ȫ���������������Ĵ���
    // -noproxy (or -proxy=0) as well as the empty string can be used to not set a proxy, this is the default // -noproxy���� -proxy=0���Լ����ַ������ڲ����ô�������Ĭ��ֵ
    std::string proxyArg = GetArg("-proxy", ""); // ����ѡ�ָ�������ַ��Ĭ��Ϊ ""
    if (proxyArg != "" && proxyArg != "0") { // ֵ�� 0 �� �ǿձ�ʾ�����˴���
        proxyType addrProxy = proxyType(CService(proxyArg, 9050), proxyRandomize); // ���ô����ַ�Ͷ˿ڣ��˿�Ĭ��Ϊ 9050
        if (!addrProxy.IsValid()) // ��֤�����ַ����Ч��
            return InitError(strprintf(_("Invalid -proxy address: '%s'"), proxyArg));

        SetProxy(NET_IPV4, addrProxy); // ���� IPV4 ����
        SetProxy(NET_IPV6, addrProxy); // ���� IPV6 ����
        SetProxy(NET_TOR, addrProxy); // ���� TOR ���·�ɴ���
        SetNameProxy(addrProxy); // �������ִ���
        SetReachable(NET_TOR); // by default, -proxy sets onion as reachable, unless -noonion later
    }

    // -onion can be used to set only a proxy for .onion, or override normal proxy for .onion addresses // -onion ѡ�����ڽ�Ϊ .onion ���ô����򸲸� .onion ��ַ����ͨ����
    // -noonion (or -onion=0) disables connecting to .onion entirely // -noonion���� -onion=0����ȫ�ر����ӵ� .onion
    // An empty string is used to not override the onion proxy (in which case it defaults to -proxy set above, or none) // ���ַ������ڲ�������д����ڴ�����£�Ĭ�� -proxy �������棬���ޣ�
    std::string onionArg = GetArg("-onion", ""); // ���·��ѡ�Ĭ�Ϲر�
    if (onionArg != "") { // ֵ�ǿ�ʱ
        if (onionArg == "0") { // Handle -noonion/-onion=0
            SetReachable(NET_TOR, false); // set onions as unreachable
        } else { // �������·��
            proxyType addrOnion = proxyType(CService(onionArg, 9050), proxyRandomize); // �������·�ɵ�ַ�Ͷ˿�
            if (!addrOnion.IsValid()) // ������·�ɵ�ַ������
                return InitError(strprintf(_("Invalid -onion address: '%s'"), onionArg));
            SetProxy(NET_TOR, addrOnion); // ������д���
            SetReachable(NET_TOR); // �����������ɴ�
        }
    }

    // see Step 2: parameter interactions for more information about these // 6.��ȡ���������Ϣ���鿴�ڶ�������������
    fListen = GetBoolArg("-listen", DEFAULT_LISTEN); // ����ѡ�Ĭ�Ͽ���
    fDiscover = GetBoolArg("-discover", true); // ����ѡ�Ĭ�Ͽ���
    fNameLookup = GetBoolArg("-dns", DEFAULT_NAME_LOOKUP); // dns ���ַ��֣�Ĭ�ϴ�

    bool fBound = false; // ��״̬����ʼ��Ϊ false
    if (fListen) { // Ĭ�� true
        if (mapArgs.count("-bind") || mapArgs.count("-whitebind")) { // ָ���� -bind ѡ��� -whitebind
            BOOST_FOREACH(const std::string& strBind, mapMultiArgs["-bind"]) { // ���� bind ��ַ
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false)) // ���� bind ��ַ
                    return InitError(strprintf(_("Cannot resolve -bind address: '%s'"), strBind));
                fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR)); // bind ��ָ����ַ
            }
            BOOST_FOREACH(const std::string& strBind, mapMultiArgs["-whitebind"]) { // �������󶨵İ�����
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, 0, false))
                    return InitError(strprintf(_("Cannot resolve -whitebind address: '%s'"), strBind));
                if (addrBind.GetPort() == 0)
                    return InitError(strprintf(_("Need to specify a port with -whitebind: '%s'"), strBind));
                fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR | BF_WHITELIST));
            }
        }
        else { // δ���� bind
            struct in_addr inaddr_any;
            inaddr_any.s_addr = INADDR_ANY; // ��������ַ����
            fBound |= Bind(CService(in6addr_any, GetListenPort()), BF_NONE); // �󶨱��� ipv6
            fBound |= Bind(CService(inaddr_any, GetListenPort()), !fBound ? BF_REPORT_ERROR : BF_NONE); // �󶨱��� ipv4��0.0.0.0:port ��ʾ���е�ַ �� �����ַ
        }
        if (!fBound) // !false ��ʧ�ܣ���¼������־���˳�
            return InitError(_("Failed to listen on any port. Use -listen=0 if you want this."));
    }

    if (mapArgs.count("-externalip")) { // �ⲿ�� ip ��ַѡ��
        BOOST_FOREACH(const std::string& strAddr, mapMultiArgs["-externalip"]) { // ����ָ�����ⲿ ip ��ַ
            CService addrLocal(strAddr, GetListenPort(), fNameLookup); // ����һ�����ӣ���ַ�Ͷ˿ڣ�����
            if (!addrLocal.IsValid()) // ��֤��ַ��Ч��
                return InitError(strprintf(_("Cannot resolve -externalip address: '%s'"), strAddr));
            AddLocal(CService(strAddr, GetListenPort(), fNameLookup), LOCAL_MANUAL); // ��ӵ���������ӳ���б�
        }
    }

    BOOST_FOREACH(const std::string& strDest, mapMultiArgs["-seednode"]) // ������ӵ����ӽڵ� IP ��ַ
        AddOneShot(strDest); // ����˫�˶��� vOneShots

#if ENABLE_ZMQ // 7.���� ZeroMQ ѡ�һ��Ƕ��ʽ���������ӿ⣬������ Socket ��һϵ�нӿ�
    pzmqNotificationInterface = CZMQNotificationInterface::CreateWithArguments(mapArgs); // ��ʼ��

    if (pzmqNotificationInterface) {
        RegisterValidationInterface(pzmqNotificationInterface); // ע�� zmq ֪ͨ�ӿ�
    }
#endif
    if (mapArgs.count("-maxuploadtarget")) { // 8.���Ա�������������ڸ���Ŀ��ֵ
        CNode::SetMaxOutboundTarget(GetArg("-maxuploadtarget", DEFAULT_MAX_UPLOAD_TARGET)*1024*1024); // Ĭ��Ϊ 0 ��ʾ������
    }

    // ********************************************************* Step 7: load block chain // �������������ݣ���������Ŀ¼ .bitcoin/blocks/��

    fReindex = GetBoolArg("-reindex", false); // ��������־���������� rev �ļ�����Ĭ�Ϲر�

    // Upgrading to 0.8; hard-link the old blknnnn.dat files into /blocks/ // 1.������ 0.8��Ӳ���Ӿɵ����������ļ� blknnnn.dat �� /blocks/ Ŀ¼��
    boost::filesystem::path blocksDir = GetDataDir() / "blocks"; // �����ϰ�������ʽ�������ļ�����
    if (!boost::filesystem::exists(blocksDir)) // ����Ŀ¼������
    {
        boost::filesystem::create_directories(blocksDir); // �򴴽���������Ŀ¼
        bool linked = false;
        for (unsigned int i = 1; i < 10000; i++) { // ����ԭ���������ļ�
            boost::filesystem::path source = GetDataDir() / strprintf("blk%04u.dat", i); // �ɰ����������ļ���
            if (!boost::filesystem::exists(source)) break;
            boost::filesystem::path dest = blocksDir / strprintf("blk%05u.dat", i-1); // �°����������ļ�����ͳһ���� blocks Ŀ¼��
            try {
                boost::filesystem::create_hard_link(source, dest); // �����ھɰ����������ļ�������Ӳ���ӣ��Լ����°�
                LogPrintf("Hardlinked %s -> %s\n", source.string(), dest.string());
                linked = true; // �����ӱ�־����Ϊ true
            } catch (const boost::filesystem::filesystem_error& e) {
                // Note: hardlink creation failing is not a disaster, it just means
                // blocks will get re-downloaded from peers.
                LogPrintf("Error hardlinking blk%04u.dat: %s\n", i, e.what());
                break;
            }
        }
        if (linked) // ��������Ӳ���ӣ���������������־Ϊ true
        {
            fReindex = true;
        }
    }

    // cache size calculations // 2.�����С����
    int64_t nTotalCache = (GetArg("-dbcache", nDefaultDbCache) << 20); // �ܻ����С
    nTotalCache = std::max(nTotalCache, nMinDbCache << 20); // total cache cannot be less than nMinDbCache // �ܻ��治�ܵ��� nMinDbCache
    nTotalCache = std::min(nTotalCache, nMaxDbCache << 20); // total cache cannot be greated than nMaxDbcache // �ܻ��治�ܸ��� nMaxDbcache
    int64_t nBlockTreeDBCache = nTotalCache / 8; // ���������ݿ⻺���С
    if (nBlockTreeDBCache > (1 << 21) && !GetBoolArg("-txindex", DEFAULT_TXINDEX))
        nBlockTreeDBCache = (1 << 21); // block tree db cache shouldn't be larger than 2 MiB
    nTotalCache -= nBlockTreeDBCache;
    int64_t nCoinDBCache = std::min(nTotalCache / 2, (nTotalCache / 4) + (1 << 23)); // use 25%-50% of the remainder for disk cache // �����ݿ⻺���С
    nTotalCache -= nCoinDBCache;
    nCoinCacheUsage = nTotalCache; // the rest goes to in-memory cache // �Ȼ�������
    LogPrintf("Cache configuration:\n");
    LogPrintf("* Using %.1fMiB for block index database\n", nBlockTreeDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for chain state database\n", nCoinDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for in-memory UTXO set\n", nCoinCacheUsage * (1.0 / 1024 / 1024));

    bool fLoaded = false; // ���ر�־����ʾ�������������Ƿ�ɹ�����ʼΪ false
    while (!fLoaded) { // 3.����һ��û�м��سɹ����ټ���һ��
        bool fReset = fReindex;
        std::string strLoadError;

        uiInterface.InitMessage(_("Loading block index..."));

        nStart = GetTimeMillis();
        do {
            try {
                UnloadBlockIndex(); // Ϊ���ڶ��μ��أ�����յ�ǰ����������
                delete pcoinsTip;
                delete pcoinsdbview;
                delete pcoinscatcher;
                delete pblocktree;

                pblocktree = new CBlockTreeDB(nBlockTreeDBCache, false, fReindex); // ��������
                pcoinsdbview = new CCoinsViewDB(nCoinDBCache, false, fReindex);
                pcoinscatcher = new CCoinsViewErrorCatcher(pcoinsdbview);
                pcoinsTip = new CCoinsViewCache(pcoinscatcher);

                if (fReindex) { // Ĭ�� false
                    pblocktree->WriteReindexing(true); // 3.1.д����������־Ϊ true���������ݿ� leveldb��
                    //If we're reindexing in prune mode, wipe away unusable block files and all undo data files
                    if (fPruneMode) // ����������޼�ģʽ���޼���ȷ�ϵ����飩�½�����������
                        CleanupBlockRevFiles(); // ������õĿ��ļ���blk�������лָ������ļ���rev��
                }

                if (!LoadBlockIndex()) { // 3.2.�Ӵ��̼��������������ͱ����ݿ�
                    strLoadError = _("Error loading block database");
                    break;
                }

                // If the loaded chain has a wrong genesis, bail out immediately // ������ص����Ĵ�������������ϲ���
                // (we're likely using a testnet datadir, or the other way around). // �����ǿ���ʹ�ò�����������Ŀ¼�������෴����
                if (!mapBlockIndex.empty() && mapBlockIndex.count(chainparams.GetConsensus().hashGenesisBlock) == 0) // ��� mapBlockIndex �Ƿ�Ϊ�գ����Ƿ�����˴�������������ͨ����ϣ���ң�
                    return InitError(_("Incorrect or no genesis block found. Wrong datadir for network?"));

                // Initialize the block index (no-op if non-empty database was already loaded) // ��ʼ����������(����ǿ����ݿ��Ѿ��������޲���)
                if (!InitBlockIndex(chainparams)) { // 3.3.��ʼ����������������
                    strLoadError = _("Error initializing block database");
                    break;
                }

                // Check for changed -txindex state // ��� -txindex �ı��״̬
                if (fTxIndex != GetBoolArg("-txindex", DEFAULT_TXINDEX)) { // ��� fTxIndex ��־���� LoadBlockIndex �����п��ܱ��ı�
                    strLoadError = _("You need to rebuild the database using -reindex to change -txindex");
                    break;
                }

                // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks // ��� -prune �ı��״̬�����ǹ�ע��ʱ��ȥ���޼��������飬
                // in the past, but is now trying to run unpruned. // �����ڳ�������δ�޼��������顣
                if (fHavePruned && !fPruneMode) { // ��� fHavePruned ��־���û�ɾ��һЩ�ļ���������δ�޼�ģʽ������ 
                    strLoadError = _("You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain");
                    break;
                }

                uiInterface.InitMessage(_("Verifying blocks...")); // ��ʼ��֤����
                if (fHavePruned && GetArg("-checkblocks", DEFAULT_CHECKBLOCKS) > MIN_BLOCKS_TO_KEEP) { // pending
                    LogPrintf("Prune: pruned datadir may not have more than %d blocks; -checkblocks=%d may fail\n",
                        MIN_BLOCKS_TO_KEEP, GetArg("-checkblocks", DEFAULT_CHECKBLOCKS));
                }

                {
                    LOCK(cs_main);
                    CBlockIndex* tip = chainActive.Tip(); // ��ȡ�����������������
                    if (tip && tip->nTime > GetAdjustedTime() + 2 * 60 * 60) { // ��������ʱ�䲻�ܱȵ�ǰʱ��� 2h
                        strLoadError = _("The block database contains a block which appears to be from the future. "
                                "This may be due to your computer's date and time being set incorrectly. "
                                "Only rebuild the block database if you are sure that your computer's date and time are correct");
                        break;
                    }
                }

                if (!CVerifyDB().VerifyDB(chainparams, pcoinsdbview, GetArg("-checklevel", DEFAULT_CHECKLEVEL),
                              GetArg("-checkblocks", DEFAULT_CHECKBLOCKS))) { // ��֤���ݿ⣬��֤�ȼ�Ĭ�� 3����֤����Ĭ�� 288
                    strLoadError = _("Corrupted block database detected");
                    break;
                }
            } catch (const std::exception& e) {
                if (fDebug) LogPrintf("%s\n", e.what());
                strLoadError = _("Error opening block database");
                break;
            }

            fLoaded = true; // ���سɹ�
        } while(false);

        if (!fLoaded) { // 3.4.������ʧ��
            // first suggest a reindex // �״ν���������
            if (!fReset) { // =fReindex
                bool fRet = uiInterface.ThreadSafeMessageBox(
                    strLoadError + ".\n\n" + _("Do you want to rebuild the block database now?"),
                    "", CClientUIInterface::MSG_ERROR | CClientUIInterface::BTN_ABORT); // ������������� qt
                if (fRet) {
                    fReindex = true; // ��������־��Ϊ true���´��ټ�����������
                    fRequestShutdown = false; // ����رձ�־��Ϊ false
                } else {
                    LogPrintf("Aborted block database rebuild. Exiting.\n");
                    return false;
                }
            } else {
                return InitError(strLoadError);
            }
        }
    } // end of while load

    // As LoadBlockIndex can take several minutes, it's possible the user // LoadBlockIndex �Ứ�����ӣ������һ�β����ڼ䣬�û���������ر� GUI��
    // requested to kill the GUI during the last operation. If so, exit. // ��ˣ����˳���
    // As the program has not fully started yet, Shutdown() is possibly overkill. // �����ǻ�δ��ȫ������Shutdown() ����ɱ��������
    if (fRequestShutdown) // ���û��ڼ��������ڼ�����ر�
    {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false; // ������ Shutdown() ֱ���˳�
    }
    LogPrintf(" block index %15dms\n", GetTimeMillis() - nStart); // ��¼��������ʱ��

    boost::filesystem::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME; // ƴ�ӷ��ù����ļ�·��
    CAutoFile est_filein(fopen(est_path.string().c_str(), "rb"), SER_DISK, CLIENT_VERSION); // �򿪣��״δ��������ļ������������ļ�����
    // Allowed to fail as this file IS missing on first startup. // ����ʧ�ܣ���Ϊ�״�����ʱ���ļ������ڡ�
    if (!est_filein.IsNull()) // �����ļ�����
        mempool.ReadFeeEstimates(est_filein); // �ڴ�ض�ȡ���Ʒ���
    fFeeEstimatesInitialized = true; // ���ù��Ƴ�ʼ��״̬��־��Ϊ true

    // ********************************************************* Step 8: load wallet // ������Ǯ�����ܣ������Ǯ��
#ifdef ENABLE_WALLET // 1.Ǯ����Ч�ĺ�
    if (fDisableWallet) { // Ĭ�� false
        pwalletMain = NULL; // Ǯ��ָ���ÿ�
        LogPrintf("Wallet disabled!\n");
    } else {

        // needed to restore wallet transaction meta data after -zapwallettxes // ��Ҫ�� -zapwallettxes ��ָ�Ǯ������Ԫ����
        std::vector<CWalletTx> vWtx; // Ǯ�������б�

        if (GetBoolArg("-zapwallettxes", false)) { // ����Ǯ������ѡ�Ĭ�Ϲر�
            uiInterface.InitMessage(_("Zapping all transactions from wallet..."));

            pwalletMain = new CWallet(strWalletFile); // 1.1.��������ʼ��Ǯ������
            DBErrors nZapWalletRet = pwalletMain->ZapWalletTx(vWtx); // ��Ǯ���з������н��׵�Ǯ�������б�
            if (nZapWalletRet != DB_LOAD_OK) {
                uiInterface.InitMessage(_("Error loading wallet.dat: Wallet corrupted"));
                return false;
            }

            delete pwalletMain; // ɾ��Ǯ������
            pwalletMain = NULL; // ָ���ÿ�
        }

        uiInterface.InitMessage(_("Loading wallet...")); // ��ʼ����Ǯ��

        nStart = GetTimeMillis(); // ��ȡ��ǰʱ��
        bool fFirstRun = true; // �״����б�־����ʼΪ true
        pwalletMain = new CWallet(strWalletFile); // 1.2.�����µ�Ǯ������
        DBErrors nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun); // ����Ǯ�����ڴ棨��ֵ�ԣ�
        if (nLoadWalletRet != DB_LOAD_OK) // ����Ǯ��״̬����
        {
            if (nLoadWalletRet == DB_CORRUPT)
                strErrors << _("Error loading wallet.dat: Wallet corrupted") << "\n";
            else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
            {
                InitWarning(_("Error reading wallet.dat! All keys read correctly, but transaction data"
                             " or address book entries might be missing or incorrect."));
            }
            else if (nLoadWalletRet == DB_TOO_NEW)
                strErrors << _("Error loading wallet.dat: Wallet requires newer version of Bitcoin Core") << "\n";
            else if (nLoadWalletRet == DB_NEED_REWRITE)
            {
                strErrors << _("Wallet needed to be rewritten: restart Bitcoin Core to complete") << "\n";
                LogPrintf("%s", strErrors.str());
                return InitError(strErrors.str());
            }
            else
                strErrors << _("Error loading wallet.dat") << "\n";
        } // ����Ǯ���ɹ�

        if (GetBoolArg("-upgradewallet", fFirstRun)) // 1.3.����Ǯ��ѡ��״����б�־������Ӧ��Ϊ false
        {
            int nMaxVersion = GetArg("-upgradewallet", 0);
            if (nMaxVersion == 0) // the -upgradewallet without argument case
            {
                LogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST); // 60000
                nMaxVersion = CLIENT_VERSION; // ���汾Ϊ��ǰ�ͻ��˰汾
                pwalletMain->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately // �������õ�����С�汾
            }
            else
                LogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
            if (nMaxVersion < pwalletMain->GetVersion()) // �����汾С�ڵ�ǰǮ���汾
                strErrors << _("Cannot downgrade wallet") << "\n";
            pwalletMain->SetMaxVersion(nMaxVersion); // �������汾
        }

        if (fFirstRun) // 1.4.�����״�����
        {
            // Create new keyUser and set as default key // �������û���Կ������ΪĬ����Կ
            RandAddSeedPerfmon(); // ���������

            CPubKey newDefaultKey; // �¹�Կ����
            if (pwalletMain->GetKeyFromPool(newDefaultKey)) { // ��Կ�׳�ȡһ����Կ
                pwalletMain->SetDefaultKey(newDefaultKey); // ���øù�ԿΪĬ�Ϲ�Կ
                if (!pwalletMain->SetAddressBook(pwalletMain->vchDefaultKey.GetID(), "", "receive")) // ����Ĭ�Ϲ�Կ����ַ��Ĭ���˻� "" �£�������Ŀ��Ϊ����
                    strErrors << _("Cannot write default address") << "\n";
            }

            pwalletMain->SetBestChain(chainActive.GetLocator()); // ��Ǯ���������������¼��ѿ��λ��
        }

        LogPrintf("%s", strErrors.str());
        LogPrintf(" wallet      %15dms\n", GetTimeMillis() - nStart); // ��¼Ǯ�����ص�ʱ��

        RegisterValidationInterface(pwalletMain); // ע��һ��Ǯ�����ڽ��� bitcoin core ������

        CBlockIndex *pindexRescan = chainActive.Tip(); // ��ȡ������������
        if (GetBoolArg("-rescan", false)) // 1.5.��ɨ��ѡ�Ĭ�Ϲر�
            pindexRescan = chainActive.Genesis(); // ��ȡ��ǰ���Ĵ�����������
        else
        {
            CWalletDB walletdb(strWalletFile); // ͨ��Ǯ���ļ�������Ǯ�����ݿ����
            CBlockLocator locator;
            if (walletdb.ReadBestBlock(locator)) // ��ȡ��������λ��
                pindexRescan = FindForkInGlobalIndex(chainActive, locator); // �ڼ���������������������µ�һ��������
            else
                pindexRescan = chainActive.Genesis();
        }
        if (chainActive.Tip() && chainActive.Tip() != pindexRescan) // ����Ǵ�������Ҳ�Ƿֲ�����
        {
            //We can't rescan beyond non-pruned blocks, stop and throw an error // �����޷���ɨ�賬�����޼������飬ֹͣ���׳�һ������
            //this might happen if a user uses a old wallet within a pruned node // ����û������޼��ڵ���ʹ�þ�Ǯ�������ڸ���ʱ�������е� -disablewallet��
            // or if he ran -disablewallet for a longer time, then decided to re-enable // ����ܷ������������
            if (fPruneMode) // �޼�ģʽ��־��Ĭ��Ϊ false
            {
                CBlockIndex *block = chainActive.Tip(); // ��ȡ�����������������
                while (block && block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA) && block->pprev->nTx > 0 && pindexRescan != block) // �ҵ� pindexRescan ����Ӧ����
                    block = block->pprev;

                if (pindexRescan != block)
                    return InitError(_("Prune: last wallet synchronisation goes beyond pruned data. You need to -reindex (download the whole blockchain again in case of pruned node)"));
            }

            uiInterface.InitMessage(_("Rescanning...")); // ��ʼ��ɨ��
            LogPrintf("Rescanning last %i blocks (from block %i)...\n", chainActive.Height() - pindexRescan->nHeight, pindexRescan->nHeight); // ��¼�� pindexRescan->nHeight ��ʼ��ɨ����������
            nStart = GetTimeMillis(); // ��¼��ɨ��Ŀ�ʼʱ��
            pwalletMain->ScanForWalletTransactions(pindexRescan, true); // ��ɨ��Ǯ������
            LogPrintf(" rescan      %15dms\n", GetTimeMillis() - nStart); // ��¼��ɨ�����ʱ
            pwalletMain->SetBestChain(chainActive.GetLocator()); // ������������ڴ桢���ݿ⣩
            nWalletDBUpdated++; // Ǯ�����ݿ����������� 1

            // Restore wallet transaction metadata after -zapwallettxes=1 // �� zapwallettxes ѡ������ģʽ 1 �󣬻ָ�Ǯ������Ԫ����
            if (GetBoolArg("-zapwallettxes", false) && GetArg("-zapwallettxes", "1") != "2")
            { // ��ѡ�����û�ɾ������Ǯ��������ֻ�ָ�������ʱͨ��ʹ�� -rescan ��ɨ��ѡ��Ĳ�����������ģʽ��
                CWalletDB walletdb(strWalletFile); // ����Ǯ�����ݿ����

                BOOST_FOREACH(const CWalletTx& wtxOld, vWtx) // ����Ǯ�������б�
                {
                    uint256 hash = wtxOld.GetHash(); // ��ȡǮ�����׹�ϣ
                    std::map<uint256, CWalletTx>::iterator mi = pwalletMain->mapWallet.find(hash); // ��Ǯ��ӳ�佻��ӳ���б��в��Ҹý���
                    if (mi != pwalletMain->mapWallet.end()) // ���ҵ�
                    { // ���¸ñ�Ǯ������
                        const CWalletTx* copyFrom = &wtxOld;
                        CWalletTx* copyTo = &mi->second;
                        copyTo->mapValue = copyFrom->mapValue;
                        copyTo->vOrderForm = copyFrom->vOrderForm;
                        copyTo->nTimeReceived = copyFrom->nTimeReceived;
                        copyTo->nTimeSmart = copyFrom->nTimeSmart;
                        copyTo->fFromMe = copyFrom->fFromMe;
                        copyTo->strFromAccount = copyFrom->strFromAccount;
                        copyTo->nOrderPos = copyFrom->nOrderPos;
                        copyTo->WriteToDisk(&walletdb); // д��Ǯ�������ļ���
                    }
                }
            }
        }
        pwalletMain->SetBroadcastTransactions(GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST)); // ���ù㲥���ף�Ĭ��Ϊ true
    } // (!fDisableWallet)
#else // 2.!ENABLE_WALLET
    LogPrintf("No wallet support compiled in!\n");
#endif // !ENABLE_WALLET

    // ********************************************************* Step 9: data directory maintenance // ���ǲü�ģʽ�ҹر���������ѡ������ blockstore �Ĳü�

    // if pruning, unset the service bit and perform the initial blockstore prune // ��������޼���
    // after any wallet rescanning has taken place. // ���κ�Ǯ����ɨ�跢����ȡ�����÷���λ��ִ�г�ʼ����洢�޼���
    if (fPruneMode) { // �ü���־��Ĭ��Ϊ false
        LogPrintf("Unsetting NODE_NETWORK on prune mode\n");
        nLocalServices &= ~NODE_NETWORK; // ȡ�����ñ��ط����е� NODE_NETWORK
        if (!fReindex) { // ����������־�ر�
            uiInterface.InitMessage(_("Pruning blockstore...")); // ��ʼ�޼�����洢
            PruneAndFlush(); // �����޼���־��ˢ�´����ϵ���״̬
        }
    }

    // ********************************************************* Step 10: import blocks // ������������

    if (mapArgs.count("-blocknotify")) // 1.��ע��������֪ͨ������
        uiInterface.NotifyBlockTip.connect(BlockNotifyCallback); // ��������֪ͨ�ص�����

    uiInterface.InitMessage(_("Activating best chain..."));
    // scan for better chains in the block chain database, that are not yet connected in the active best chain // ɨ�����������ݿ��е����������Щ����û���ӵ�����������
    CValidationState state;
    if (!ActivateBestChain(state, chainparams)) // 2.���������������ȡ��֤״̬
        strErrors << "Failed to connect best block";

    std::vector<boost::filesystem::path> vImportFiles; // �����ļ��б���ŵ��������ļ���·����
    if (mapArgs.count("-loadblock")) // ���������ļ�ѡ��
    {
        BOOST_FOREACH(const std::string& strFile, mapMultiArgs["-loadblock"]) // 3.����ָ���������ļ�
            vImportFiles.push_back(strFile); // �����ļ��б�
    }
    threadGroup.create_thread(boost::bind(&ThreadImport, vImportFiles)); // 4.����һ�����ڵ��������߳�
    if (chainActive.Tip() == NULL) { // ���ٴ�������Ҫ�������
        LogPrintf("Waiting for genesis block to be imported...\n");
        while (!fRequestShutdown && chainActive.Tip() == NULL) // ���뱣֤���ټ��ش�������
            MilliSleep(10); // ����˯ 10ms �ȴ����������߳���ɹ���
    }

    // ********************************************************* Step 11: start node // �����ڵ���񣬼������� P2P �����ڿ��߳�

    if (!CheckDiskSpace()) // 1.���Ӳ��ʣ��ռ��Ƿ���㣨���� 50MB�������ڽ��ղ��洢������
        return false; // ���ռ䲻�㣬���� false �˳�

    if (!strErrors.str().empty()) // 2.���ǰ��ĳ�ʼ�������Ƿ��д�����Ϣ
        return InitError(strErrors.str()); // �����ڴ�����Ϣ�����ش�����Ϣ���˳�

    RandAddSeedPerfmon(); // 3.���ڸ�Ǯ���������˽Կ����

    //// debug print // 4.���Դ�ӡ����¼�����Ϣ
    LogPrintf("mapBlockIndex.size() = %u\n",   mapBlockIndex.size()); // ����������С
    LogPrintf("nBestHeight = %d\n",                   chainActive.Height()); // ����������߶�
#ifdef ENABLE_WALLET
    LogPrintf("setKeyPool.size() = %u\n",      pwalletMain ? pwalletMain->setKeyPool.size() : 0); // Ǯ������Կ�ش�С
    LogPrintf("mapWallet.size() = %u\n",       pwalletMain ? pwalletMain->mapWallet.size() : 0); // Ǯ�������б��С
    LogPrintf("mapAddressBook.size() = %u\n",  pwalletMain ? pwalletMain->mapAddressBook.size() : 0); // Ǯ���ڵ�ַ���Ĵ�С
#endif

    if (GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION)) // 5.�������·�ɣ�Ĭ�ϴ�
        StartTorControl(threadGroup, scheduler);

    StartNode(threadGroup, scheduler); // 6.���������߳�

    // Monitor the chain, and alert if we get blocks much quicker or slower than expected
    // The "bad chain alert" scheduler has been disabled because the current system gives far
    // too many false positives, such that users are starting to ignore them.
    // This code will be disabled for 0.12.1 while a fix is deliberated in #7568
    // this was discussed in the IRC meeting on 2016-03-31.
    //
    // --- disabled ---
    //int64_t nPowTargetSpacing = Params().GetConsensus().nPowTargetSpacing;
    //CScheduler::Function f = boost::bind(&PartitionCheck, &IsInitialBlockDownload,
    //                                     boost::ref(cs_main), boost::cref(pindexBestHeader), nPowTargetSpacing);
    //scheduler.scheduleEvery(f, nPowTargetSpacing);
    // --- end disabled ---

    // Generate coins in the background // 7.�ڿ����ã��������رң���¼����
    GenerateBitcoins(GetBoolArg("-gen", DEFAULT_GENERATE), GetArg("-genproclimit", DEFAULT_GENERATE_THREADS), chainparams); // �����ڿ��̣߳�Ĭ�Ϲرգ��߳���Ĭ��Ϊ 1��0 ��ʾ��ֹ�ڿ�-1 ��ʾ CPU ������

    // ********************************************************* Step 12: finished // ���

    SetRPCWarmupFinished(); // ���� RPC Ԥ�������
    uiInterface.InitMessage(_("Done loading")); // ��ʾ���������Ϣ

#ifdef ENABLE_WALLET
    if (pwalletMain) {
        // Add wallet transactions that aren't already in a block to mapTransactions
        pwalletMain->ReacceptWalletTransactions(); // ���½���Ǯ�����ף���Ǯ�������еĽ�����ӵ��ڴ����

        // Run a thread to flush wallet periodically
        threadGroup.create_thread(boost::bind(&ThreadFlushWalletDB, boost::ref(pwalletMain->strWalletFile))); // ����ˢ��Ǯ���߳�
    }
#endif

    return !fRequestShutdown;
}
