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
CWallet* pwalletMain = NULL; // 指向主钱包对象的指针
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
// anyway. // Win32 LevelDB 不使用文件描述符，用于访问块文件的不会计入 fd_set 大小限制。
#define MIN_CORE_FILEDESCRIPTORS 0 // Windows
#else
#define MIN_CORE_FILEDESCRIPTORS 150 // Unix/Linux
#endif

/** Used to pass flags to the Bind() function */ // 用于 Bind() 函数的标志
enum BindFlags { // 绑定标志枚举
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

volatile bool fRequestShutdown = false; // 请求关闭标志，初始为 false

void StartShutdown()
{
    fRequestShutdown = true; // 把请求关闭标志置为 true
}
bool ShutdownRequested()
{
    return fRequestShutdown; // 返回当前的请求关闭标志
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
    // Writes do not need similar protection, as failure to write is handled by the caller. // 写入不需要类似的保护，因为调用失败是由调用者处理的。
};

static CCoinsViewDB *pcoinsdbview = NULL;
static CCoinsViewErrorCatcher *pcoinscatcher = NULL;
static boost::scoped_ptr<ECCVerifyHandle> globalVerifyHandle; // 该智能指针与 STL 的 std::unique_ptr 类似

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
    static CCriticalSection cs_Shutdown; // 创建关闭锁临界对象
    TRY_LOCK(cs_Shutdown, lockShutdown); // 上锁
    if (!lockShutdown)
        return;

    /// Note: Shutdown() must be able to handle cases in which AppInit2() failed part of the way,
    /// for example if the data directory was found to be locked.
    /// Be sure that anything that writes files or flushes caches only does this if the respective
    /// module was initialized.
    RenameThread("bitcoin-shutoff"); // 重命名比特币关闭线程
    mempool.AddTransactionsUpdated(1);

    StopHTTPRPC(); // 关闭 HTTP RPC 服务
    StopREST(); // 关闭 REST
    StopRPC(); // 关闭 RPC
    StopHTTPServer(); // 关闭 HTTP 服务器
#ifdef ENABLE_WALLET
    if (pwalletMain) // 若钱包存在
        pwalletMain->Flush(false); // 刷新钱包数据库后关闭
#endif
    GenerateBitcoins(false, 0, Params()); // 关闭矿工线程
    StopNode(); // 关闭节点
    StopTorControl(); // 关闭洋葱路由
    UnregisterNodeSignals(GetNodeSignals()); // 解注册所有注册的节点信号函数

    if (fFeeEstimatesInitialized) // 若费用估计已初始化
    {
        boost::filesystem::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME; // 路径拼接获取费用估计文件路径
        CAutoFile est_fileout(fopen(est_path.string().c_str(), "wb"), SER_DISK, CLIENT_VERSION); // 打开费用估计文件
        if (!est_fileout.IsNull()) // 若文件正常打开
            mempool.WriteFeeEstimates(est_fileout); // 写入估算最低交易费用和确认所需优先级的统计数据
        else
            LogPrintf("%s: Failed to write fee estimates to %s\n", __func__, est_path.string());
        fFeeEstimatesInitialized = false;
    }

    { // 同步链状态到磁盘
        LOCK(cs_main); // 上锁
        if (pcoinsTip != NULL) {
            FlushStateToDisk(); // 刷新区块状态、索引到磁盘
        }
        delete pcoinsTip;
        pcoinsTip = NULL;
        delete pcoinscatcher;
        pcoinscatcher = NULL;
        delete pcoinsdbview;
        pcoinsdbview = NULL;
        delete pblocktree; // 删除区块树数据库
        pblocktree = NULL;
    }
#ifdef ENABLE_WALLET
    if (pwalletMain)
        pwalletMain->Flush(true); // 刷新钱包
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
        boost::filesystem::remove(GetPidFile()); // 删除进程号文件
    } catch (const boost::filesystem::filesystem_error& e) {
        LogPrintf("%s: Unable to remove pidfile: %s\n", __func__, e.what());
    }
#endif
    UnregisterAllValidationInterfaces(); // 解注册所有验证接口
#ifdef ENABLE_WALLET
    delete pwalletMain; // 删除钱包堆对象
    pwalletMain = NULL; // 指针置空
#endif
    globalVerifyHandle.reset();
    ECC_Stop(); // 关闭椭圆曲线
    LogPrintf("%s: done\n", __func__); // 记录日志，关闭完成
}

/**
 * Signal handlers are very limited in what they are allowed to do, so:
 */ // 信号处理程序在允许的范围内非常有限，因此：
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
    uiInterface.ThreadSafeMessageBox(str, "", CClientUIInterface::MSG_ERROR); // 弹出消息框，提示用户
    return false;
}

bool static InitWarning(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, "", CClientUIInterface::MSG_WARNING);
    return true;
}

bool static Bind(const CService &addr, unsigned int flags) { // 绑定并获取状态
    if (!(flags & BF_EXPLICIT) && IsLimited(addr))
        return false;
    std::string strError;
    if (!BindListenPort(addr, strError, (flags & BF_WHITELIST) != 0)) { // 绑定并监听端口
        if (flags & BF_REPORT_ERROR)
            return InitError(strError);
        return false;
    }
    return true; // 成功返回 true
}

void OnRPCStopped()
{
    cvBlockChange.notify_all(); // 通知所有等待条件 cvBlockChange 的线程
    LogPrint("rpc", "RPC stopped.\n"); // 记录日志
}

void OnRPCPreCommand(const CRPCCommand& cmd)
{
    // Observe safe mode // 监控安全模式
    string strWarning = GetWarnings("rpc"); // 获取 rpc 警告信息
    if (strWarning != "" && !GetBoolArg("-disablesafemode", DEFAULT_DISABLE_SAFEMODE) &&
        !cmd.okSafeMode) // 若有警告信息 且 未禁用安全模式 且 RPC 命令非安全模式命令
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, string("Safe mode: ") + strWarning); // 抛出异常
}

std::string HelpMessage(HelpMessageMode mode)
{
    const bool showDebug = GetBoolArg("-help-debug", false); // 调试选项，默认关闭

    // When adding new options to the categories, please keep and ensure alphabetical ordering. // 当添加新选项到类别时，请确保按字母顺序排序。
    // Do not translate _(...) -help-debug options, Many technical terms, and only a very small audience, so is unnecessary stress to translators. // 不要翻译  _(...) -help-debug 选项，许多技术术语，只有非常小的受众，所以对译者来说是不必要的压力。
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

    return strUsage; // 返回用法字符串
}

std::string LicenseInfo() // 许可证信息
{
    // todo: remove urls from translations on next change // todo：在下次更改时从翻译中移除 urls
    return FormatParagraph(strprintf(_("Copyright (C) 2009-%i The Bitcoin Core Developers"), COPYRIGHT_YEAR)) + "\n" +
           "\n" +
           FormatParagraph(_("This is experimental software.")) + "\n" +
           "\n" +
           FormatParagraph(_("Distributed under the MIT software license, see the accompanying file COPYING or <http://www.opensource.org/licenses/mit-license.php>.")) + "\n" +
           "\n" +
           FormatParagraph(_("This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit <https://www.openssl.org/> and cryptographic software written by Eric Young and UPnP software written by Thomas Bernard.")) +
           "\n"; // 返回格式化的文本信息
}

static void BlockNotifyCallback(bool initialSync, const CBlockIndex *pBlockIndex)
{
    if (initialSync || !pBlockIndex)
        return;

    std::string strCmd = GetArg("-blocknotify", ""); // 获取指定的命令

    boost::replace_all(strCmd, "%s", pBlockIndex->GetBlockHash().GetHex()); // 替换最佳区块哈希的 16 进制形式
    boost::thread t(runCommand, strCmd); // thread runs free // 传入命令，运行处理命令线程
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
// works correctly. // 如果我们同时使用 -prune 和 -reindex，然后删除将被再索引忽略的区块文件。因为再索引的工作原理是从区块文件 0 开始循环知道一个区块文件丢失，所以在此执行相同的操作来删除丢失文件后续的区块文件。同时删除所有恢复文件，因为它们将通过再索引重写。这确保了区块文件与我们开始下载时实际在磁盘上的内容同步，因此修剪工作正常。
void CleanupBlockRevFiles() // 删除某个缺失区块之后的所有区块数据，和前缀为 rev 的文件
{
    using namespace boost::filesystem;
    map<string, path> mapBlockFiles; // <区块文件索引（?????）, 区块文件路径（path）>

    // Glob all blk?????.dat and rev?????.dat files from the blocks directory. // 从区块目录全部区块和恢复数据文件。
    // Remove the rev files immediately and insert the blk file paths into an // 立刻移除恢复文件并把区块文件路径
    // ordered map keyed by block file index. // 插入一个键为区块文件索引的有序映射列表中。
    LogPrintf("Removing unusable blk?????.dat and rev?????.dat files for -reindex with -prune\n");
    path blocksdir = GetDataDir() / "blocks"; // 拼接区块数据目录
    for (directory_iterator it(blocksdir); it != directory_iterator(); it++) { // 遍历区块目录下的文件（directory_iterator 默认构造函数，指向目录尾部）
        if (is_regular_file(*it) && // 如果是普通文件，且
            it->path().filename().string().length() == 12 && // 文件名的长度为 12，且
            it->path().filename().string().substr(8,4) == ".dat") // 后 4 个字符为 ".dat"
        { // 文件校验（包括文件名，文件格式）
            if (it->path().filename().string().substr(0,3) == "blk") // 若为区块文件
                mapBlockFiles[it->path().filename().string().substr(3,5)] = it->path();  // 把区块文件索引与该文件路径配对插入去快文件映射列表中
            else if (it->path().filename().string().substr(0,3) == "rev") // 若为恢复文件
                remove(it->path()); // 移除 rev 文件
        }
    }

    // Remove all block files that aren't part of a contiguous set starting at // 通过维持单独的计数器，
    // zero by walking the ordered map (keys are block file indices) by // 遍历有序映射列表（键为区块文件索引）
    // keeping a separate counter.  Once we hit a gap (or if 0 doesn't exist) // 删除所有不属于从 0 开始的连续块文件
    // start removing block files. // 一旦我们抵达间断的区块（或 0 不存在），则开始删除区块文件。
    int nContigCounter = 0; // 检查缺失的 blk 文件，删除缺失的 blk 后的所有 blk 文件
    BOOST_FOREACH(const PAIRTYPE(string, path)& item, mapBlockFiles) {
        if (atoi(item.first) == nContigCounter) { // 从 0 开始
            nContigCounter++; // 若文件连续，计数器加 1
            continue; // 跳过该文件，比较下一个文件
        } // 否则
        remove(item.second); // 从该文件开始删除后面所有的文件
    }
}

void ThreadImport(std::vector<boost::filesystem::path> vImportFiles) // 导入区块线程处理函数
{
    const CChainParams& chainparams = Params(); // 获取区块链参数
    RenameThread("bitcoin-loadblk"); // 重命名为加载区块线程
    // -reindex // 再索引选项
    if (fReindex) {
        CImportingNow imp; // 创建导入对象，把导入标志置为 true
        int nFile = 0; // 文件序号从 0 开始
        while (true) { // 循环加载区块
            CDiskBlockPos pos(nFile, 0); // 创建区块文件位置对象
            if (!boost::filesystem::exists(GetBlockPosFilename(pos, "blk"))) // 判断该文件是否存在
                break; // No block files left to reindex // 若没有剩余区块文件用于再索引，则跳出
            FILE *file = OpenBlockFile(pos, true); // 若该文件存在，则打开
            if (!file) // 若文件打开失败
                break; // This error is logged in OpenBlockFile // 记录错误信息到日志
            LogPrintf("Reindexing block file blk%05u.dat...\n", (unsigned int)nFile);
            LoadExternalBlockFile(chainparams, file, &pos); // 加载外部的区块文件
            nFile++; // 文件号加 1
        }
        pblocktree->WriteReindexing(false); // 写入再索引标志
        fReindex = false; // 再索引置为 false
        LogPrintf("Reindexing finished\n");
        // To avoid ending up in a situation without genesis block, re-try initializing (no-op if reindexing worked): // 为避免在没有创世区块的情况下结束，再次尝试初始化（若再索引起作用了，则无操作）：
        InitBlockIndex(chainparams); // 初始化区块索引数据库
    }

    // hardcoded $DATADIR/bootstrap.dat // 硬编码的 $DATADIR/bootstrap.dat
    boost::filesystem::path pathBootstrap = GetDataDir() / "bootstrap.dat"; // 路径拼接
    if (boost::filesystem::exists(pathBootstrap)) { // 若该文件存在
        FILE *file = fopen(pathBootstrap.string().c_str(), "rb"); // 以 2 进制只读模式打开文件
        if (file) {
            CImportingNow imp;
            boost::filesystem::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
            LogPrintf("Importing bootstrap.dat...\n");
            LoadExternalBlockFile(chainparams, file); // 加载外部的区块文件
            RenameOver(pathBootstrap, pathBootstrapOld); // 重命名文件，增加 .old 后缀
        } else {
            LogPrintf("Warning: Could not open bootstrap file %s\n", pathBootstrap.string());
        }
    }

    // -loadblock= // 导入区块选项
    BOOST_FOREACH(const boost::filesystem::path& path, vImportFiles) { // 遍历待导入的区块文件路径列表
        FILE *file = fopen(path.string().c_str(), "rb"); // 以二进制只读模式打开
        if (file) {
            CImportingNow imp;
            LogPrintf("Importing blocks file %s...\n", path.string());
            LoadExternalBlockFile(chainparams, file); // 加载外部区块文件到内存
        } else {
            LogPrintf("Warning: Could not open blocks file %s\n", path.string());
        }
    }

    if (GetBoolArg("-stopafterblockimport", DEFAULT_STOPAFTERBLOCKIMPORT)) { // 导入区块后停止
        LogPrintf("Stopping after block import\n");
        StartShutdown(); // 关闭客户端
    }
}

/** Sanity checks
 *  Ensure that Bitcoin is running in a usable environment with all
 *  necessary library support.
 */ // 完整性检查。确保比特币在具有全部必备库支持的可用环境里运行。
bool InitSanityCheck(void)
{
    if(!ECC_InitSanityCheck()) { // 1.椭圆曲线密码学初始化完整性检查
        InitError("Elliptic curve cryptography sanity check failure. Aborting.");
        return false;
    }
    if (!glibc_sanity_test() || !glibcxx_sanity_test()) // 2.glibc 和 glibcxx 完整性测试
        return false;

    return true; // 检查通过返回 true
}

bool AppInitServers(boost::thread_group& threadGroup)
{
    RPCServer::OnStopped(&OnRPCStopped); // 1.连接停止 RPC 信号函数
    RPCServer::OnPreCommand(&OnRPCPreCommand); // 2.连接监控安全模式信号函数
    if (!InitHTTPServer()) //3. 初始化 HTTP 服务
        return false;
    if (!StartRPC()) // 4.启动 RPC 远程过程调用
        return false;
    if (!StartHTTPRPC()) // 5.启动 HTTP RPC（这里注册的 RPC 处理函数）
        return false;
    if (GetBoolArg("-rest", DEFAULT_REST_ENABLE) && !StartREST()) // 6.启动 REST 服务，默认关闭
        return false;
    if (!StartHTTPServer()) // 7.启动 HTTP 服务
        return false;
    return true;
}

// Parameter interaction based on rules // 基于规则的参数交互
void InitParameterInteraction()
{
    // when specifying an explicit binding address, you want to listen on it // 在指定显示绑定的地址时，
    // even when -connect or -proxy is specified // 尽管指定了 -connect 和 -proxy 选项，你也要监听它
    if (mapArgs.count("-bind")) { // 若绑定了指定地址
        if (SoftSetBoolArg("-listen", true)) // 同时监听该地址
            LogPrintf("%s: parameter interaction: -bind set -> setting -listen=1\n", __func__);
    }
    if (mapArgs.count("-whitebind")) { // 白名单绑定同上
        if (SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -whitebind set -> setting -listen=1\n", __func__);
    }

    if (mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0) { // 若连接了指定地址的节点
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default // 当只连接可信节点时，不使用 DNS 种子或默认监听
        if (SoftSetBoolArg("-dnsseed", false)) // 关闭 dnsseed
            LogPrintf("%s: parameter interaction: -connect set -> setting -dnsseed=0\n", __func__);
        if (SoftSetBoolArg("-listen", false)) // 关闭 listen
            LogPrintf("%s: parameter interaction: -connect set -> setting -listen=0\n", __func__);
    }

    if (mapArgs.count("-proxy")) { // 若使用了代理
        // to protect privacy, do not listen by default if a default proxy server is specified // 用于保护隐私，如果指定了默认的代理服务器，则不使用默认监听
        if (SoftSetBoolArg("-listen", false)) // 关闭监听
            LogPrintf("%s: parameter interaction: -proxy set -> setting -listen=0\n", __func__);
        // to protect privacy, do not use UPNP when a proxy is set. The user may still specify -listen=1 // 为了保护隐私，当设置了代理时不使用 UPNP。用户可能仍指定 -listen=1 来监听本地，
        // to listen locally, so don't rely on this happening through -listen below. // 所以不要通过下面的 -listen 设置依赖这种情况
        if (SoftSetBoolArg("-upnp", false)) // 关闭端口映射
            LogPrintf("%s: parameter interaction: -proxy set -> setting -upnp=0\n", __func__);
        // to protect privacy, do not discover addresses by default // 用于保护隐私，不使用默认的发现地址
        if (SoftSetBoolArg("-discover", false)) // 关闭地址发现
            LogPrintf("%s: parameter interaction: -proxy set -> setting -discover=0\n", __func__);
    }

    if (!GetBoolArg("-listen", DEFAULT_LISTEN)) { // 监听选项，默认开启
        // do not map ports or try to retrieve public IP when not listening (pointless) // 在不监听时不映射端口或尝试检索公共 IP
        if (SoftSetBoolArg("-upnp", false)) // 关闭端口映射
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -upnp=0\n", __func__);
        if (SoftSetBoolArg("-discover", false)) // 关闭地址发现
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -discover=0\n", __func__);
        if (SoftSetBoolArg("-listenonion", false)) // 关闭洋葱路由
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -listenonion=0\n", __func__);
    }

    if (mapArgs.count("-externalip")) { // 若指定了外部 ip
        // if an explicit public IP is specified, do not try to find others // 如果指定了公共 IP，则不尝试发现其他 IP
        if (SoftSetBoolArg("-discover", false)) // 关闭地址发现
            LogPrintf("%s: parameter interaction: -externalip set -> setting -discover=0\n", __func__);
    }

    if (GetBoolArg("-salvagewallet", false)) { // 若关闭了回复钱包选项
        // Rewrite just private keys: rescan to find transactions // 只重写私钥：再扫描用于发现交易
        if (SoftSetBoolArg("-rescan", true)) // 开启再扫描
            LogPrintf("%s: parameter interaction: -salvagewallet=1 -> setting -rescan=1\n", __func__);
    }

    // -zapwallettx implies a rescan // -zapwallettx 意味着再扫描
    if (GetBoolArg("-zapwallettxes", false)) { // 若关闭 zap 钱包交易选项
        if (SoftSetBoolArg("-rescan", true)) // 则开启再扫描选项
            LogPrintf("%s: parameter interaction: -zapwallettxes=<mode> -> setting -rescan=1\n", __func__);
    }

    // disable walletbroadcast and whitelistrelay in blocksonly mode // 在仅块默认中关闭钱包广播和白名单中继
    if (GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY)) { // 仅区块模式，默认关闭，若开启了
        if (SoftSetBoolArg("-whitelistrelay", false)) // 则关闭白名单中继
            LogPrintf("%s: parameter interaction: -blocksonly=1 -> setting -whitelistrelay=0\n", __func__);
#ifdef ENABLE_WALLET
        if (SoftSetBoolArg("-walletbroadcast", false)) // 同时关闭钱包广播
            LogPrintf("%s: parameter interaction: -blocksonly=1 -> setting -walletbroadcast=0\n", __func__);
#endif
    }

    // Forcing relay from whitelisted hosts implies we will accept relays from them in the first place. // 强制从白名单主机中中继表明我们将从它们（交易）所在的首个位置接受中继。
    if (GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY)) { // 百名单强制中继，默认开启
        if (SoftSetBoolArg("-whitelistrelay", true)) // 则开启白名单中继选项
            LogPrintf("%s: parameter interaction: -whitelistforcerelay=1 -> setting -whitelistrelay=1\n", __func__);
    }
}

void InitLogging()
{
    fPrintToConsole = GetBoolArg("-printtoconsole", false); // 1.打印到控制台，默认关闭
    fLogTimestamps = GetBoolArg("-logtimestamps", DEFAULT_LOGTIMESTAMPS); // 记录日志时间戳，默认打开
    fLogTimeMicros = GetBoolArg("-logtimemicros", DEFAULT_LOGTIMEMICROS); // 时间戳微秒，默认关闭
    fLogIPs = GetBoolArg("-logips", DEFAULT_LOGIPS); // 记录 IPs，默认关闭

    LogPrintf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"); // 2.n 个空行
    LogPrintf("Bitcoin version %s (%s)\n", FormatFullVersion(), CLIENT_DATE); // 记录比特币客户端版本号和构建时间
}

/** Initialize bitcoin.
 *  @pre Parameters should be parsed and config file should be read.
 */ // 初始化比特币。前提：参数应该被解析，配置文件应该被读取。
bool AppInit2(boost::thread_group& threadGroup, CScheduler& scheduler) // [P]3.11.程序初始化，共 12 步
{
    // ********************************************************* Step 1: setup // 初始化网络环境，挂接信号处理函数
#ifdef _MSC_VER // 1.设置 log 的输出级别为 WARNING 和 log 的输出文件
    // Turn off Microsoft heap dump noise // 关闭微软堆转储提示音
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400 // 2.处理中断消息
    // Disable confusing "helpful" text message on abort, Ctrl-C // 禁用 Ctrl-C 崩溃时烦人的“帮助”文本消息
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable Data Execution Prevention (DEP) // 3.启用数据执行保护（DEP）
    // Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
    // A failure is non-critical and needs no further attention! // 失败不重要，不需要在意！
#ifndef PROCESS_DEP_ENABLE
    // We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7), // 我们在这里定义它，因为 GCCs winbase.h 将此限制到 _WIN32_WINNT >= 0x0601 (Windows 7)，
    // which is not correct. Can be removed, when GCCs winbase.h is fixed! // 这是错误的。GCCs winbase.h 修复时可以删除
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL (WINAPI *PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol = (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != NULL) setProcDEPPol(PROCESS_DEP_ENABLE);
#endif

    if (!SetupNetworking()) // 4.设置 Windows 套接字
        return InitError("Initializing networking failed");

#ifndef WIN32 // 5.非 WIN32 平台，处理文件权限和相关信号
    if (GetBoolArg("-sysperms", false)) { // 若设置了系统文件权限
#ifdef ENABLE_WALLET // 若启用了钱包
        if (!GetBoolArg("-disablewallet", false)) // 且未关闭钱包功能
            return InitError("-sysperms is not allowed in combination with enabled wallet functionality");
#endif
    } else {
        umask(077); // 设置掩码
    }

    // Clean shutdown on SIGTERM // 在 SIGTERM 信号下清空关闭
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Reopen debug.log on SIGHUP // 在 SIGHUP 信号下重新打开 debug.log 文件
    struct sigaction sa_hup;
    sa_hup.sa_handler = HandleSIGHUP;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);

    // Ignore SIGPIPE, otherwise it will bring the daemon down if the client closes unexpectedly
    signal(SIGPIPE, SIG_IGN); // 忽略 SIGPIPE 信号，否则如果客户端异常关闭它会使守护进程关闭
#endif

    // ********************************************************* Step 2: parameter interactions // 参数交互设置，如：区块裁剪 prune 与交易索引 txindex 的冲突检测、文件描述符限制的检查
    const CChainParams& chainparams = Params(); // 1.获取当前的链参数

    // also see: InitParameterInteraction()

    // if using block pruning, then disable txindex // 2.如果使用区块修剪，需要禁止交易索引
    if (GetArg("-prune", 0)) { // 修剪模式（禁用交易索引），默认关闭
        if (GetBoolArg("-txindex", DEFAULT_TXINDEX)) // 交易索引（与修剪模式不兼容），默认关闭
            return InitError(_("Prune mode is incompatible with -txindex.")); // 不兼容的原因：修剪模式只保留区块头，而区块体包含的是交易索引 txid
#ifdef ENABLE_WALLET // 若开启了钱包
        if (GetBoolArg("-rescan", false)) { // 再扫描（修剪模式下不能使用，你可以使用 -reindex 再次下载整个区块链），默认关闭
            return InitError(_("Rescans are not possible in pruned mode. You will need to use -reindex which will download the whole blockchain again."));
        }
#endif
    }

    // Make sure enough file descriptors are available // 3.确保足够的文件描述符可用
    int nBind = std::max((int)mapArgs.count("-bind") + (int)mapArgs.count("-whitebind"), 1); // bind 占用的文件描述符数量
    int nUserMaxConnections = GetArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS); // 最大连入数，默认 125
    nMaxConnections = std::max(nUserMaxConnections, 0); // 记录最大连接数，默认为 125

    // Trim requested connection counts, to fit into system limitations // 修剪请求的连接数，以适应系统限制
    nMaxConnections = std::max(std::min(nMaxConnections, (int)(FD_SETSIZE - nBind - MIN_CORE_FILEDESCRIPTORS)), 0); // Linux 下一个进程同时打开的文件描述的数量为 1024，使用 ulimit -a/-n 查看
    int nFD = RaiseFileDescriptorLimit(nMaxConnections + MIN_CORE_FILEDESCRIPTORS); // windows 下直接返回 2048，linux 下返回成功提升后的值 nMaxConnections + MIN_CORE_FILEDESCRIPTORS
    if (nFD < MIN_CORE_FILEDESCRIPTORS) // 可用描述符数量不能低于 0
        return InitError(_("Not enough file descriptors available."));
    nMaxConnections = std::min(nFD - MIN_CORE_FILEDESCRIPTORS, nMaxConnections); // 选取提升前后较小的数

    if (nMaxConnections < nUserMaxConnections) // 若提升后低于 125 个，发出警告，可能是由于系统限制导致的数量减少
        InitWarning(strprintf(_("Reducing -maxconnections from %d to %d, because of system limitations."), nUserMaxConnections, nMaxConnections));

    // ********************************************************* Step 3: parameter-to-internal-flags // 参数转换为内部变量，把外部参数的设置转化为程序内部的状态（bool 型参数，开关类选项）

    fDebug = !mapMultiArgs["-debug"].empty(); // 1.调试开关，默认关闭
    // Special-case: if -debug=0/-nodebug is set, turn off debugging messages // 特殊情况：如果设置了 -debug=0/-nodebug，关闭调试信息
    const vector<string>& categories = mapMultiArgs["-debug"]; // 获取调试类别列表
    if (GetBoolArg("-nodebug", false) || find(categories.begin(), categories.end(), string("0")) != categories.end()) // 若未设置 -nodebug 选项 或 在类别列表中找到 "0" 值
        fDebug = false; // 调试标志置为 false

    // Check for -debugnet // 2.检查 -debugnet 选项
    if (GetBoolArg("-debugnet", false)) // -debugnet 参数，默认关闭，限制不支持改参数，使用 -debug=net
        InitWarning(_("Unsupported argument -debugnet ignored, use -debug=net."));
    // Check for -socks - as this is a privacy risk to continue, exit here // 检查 -socks 选项作为一个要继续下去的隐秘风险，在这里退出
    if (mapArgs.count("-socks")) // -socks 已不被支持，现只支持 SOCKS5 proxies
        return InitError(_("Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only SOCKS5 proxies are supported."));
    // Check for -tor - as this is a privacy risk to continue, exit here // 检查 -tor 选项作为一个要继续下去的隐秘风险，在这里退出
    if (GetBoolArg("-tor", false)) // -tor 参数是一个隐藏风险，现使用 -onion 参数
        return InitError(_("Unsupported argument -tor found, use -onion."));

    if (GetBoolArg("-benchmark", false)) // -benchmark 参数已不支持，使用 -debug=bench
        InitWarning(_("Unsupported argument -benchmark ignored, use -debug=bench."));

    if (GetBoolArg("-whitelistalwaysrelay", false)) // -whitelistalwaysrelay 参数不再支持，使用 -whitelistrelay 或 -whitelistforcerelay
        InitWarning(_("Unsupported argument -whitelistalwaysrelay ignored, use -whitelistrelay and/or -whitelistforcerelay."));

    // Checkmempool and checkblockindex default to true in regtest mode // 3.检查内存池和检查区块索引选项在回归测试模式下默认为 true
    int ratio = std::min<int>(std::max<int>(GetArg("-checkmempool", chainparams.DefaultConsistencyChecks() ? 1 : 0), 0), 1000000); // 1 or 0 对应 true or false，主网默认关闭
    if (ratio != 0) { // true
        mempool.setSanityCheck(1.0 / ratio); // 交易内存池设置完整性检查频率
    }
    fCheckBlockIndex = GetBoolArg("-checkblockindex", chainparams.DefaultConsistencyChecks()); // 检查区块索引标志，默认：主网、测试网关闭，回归测试网打开
    fCheckpointsEnabled = GetBoolArg("-checkpoints", DEFAULT_CHECKPOINTS_ENABLED); // 检测点可用，默认打开

    // mempool limits // 交易内存池限制选项
    int64_t nMempoolSizeMax = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000; // 内存池大小限制，默认接近 300M
    int64_t nMempoolSizeMin = GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000 * 40;
    if (nMempoolSizeMax < 0 || nMempoolSizeMax < nMempoolSizeMin)
        return InitError(strprintf(_("-maxmempool must be at least %d MB"), std::ceil(nMempoolSizeMin / 1000000.0)));

    // -par=0 means autodetect, but nScriptCheckThreads==0 means no concurrency // 4.-par=0 意味着自动检测，但 nScriptCheckThreads==0 意味这没有并发
    nScriptCheckThreads = GetArg("-par", DEFAULT_SCRIPTCHECK_THREADS); // 脚本检测线程数，默认为 0
    if (nScriptCheckThreads <= 0)
        nScriptCheckThreads += GetNumCores(); // 每个核一个脚本检测线程，默认
    if (nScriptCheckThreads <= 1)
        nScriptCheckThreads = 0;
    else if (nScriptCheckThreads > MAX_SCRIPTCHECK_THREADS)
        nScriptCheckThreads = MAX_SCRIPTCHECK_THREADS; // 最大线程数为 16

    fServer = GetBoolArg("-server", false); // 5.服务选项，3.8.已设置为 true

    // block pruning; get the amount of disk space (in MiB) to allot for block & undo files // 6.区块修剪；获取磁盘空间量（以 MiB 为单位）以分配区块和撤销文件（用于恢复链状态的反向补丁）
    int64_t nSignedPruneTarget = GetArg("-prune", 0) * 1024 * 1024; // 0 表示禁止修剪区块
    if (nSignedPruneTarget < 0) {
        return InitError(_("Prune cannot be configured with a negative value."));
    }
    nPruneTarget = (uint64_t) nSignedPruneTarget; // 0 或大于 0
    if (nPruneTarget) { // 0 表示禁止，大于 0 表示开启修剪模式
        if (nPruneTarget < MIN_DISK_SPACE_FOR_BLOCK_FILES) { // 修剪得目标大于等于 550 MB，为什么？
            return InitError(strprintf(_("Prune configured below the minimum of %d MiB.  Please use a higher number."), MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
        }
        LogPrintf("Prune configured to target %uMiB on disk for block and undo files.\n", nPruneTarget / 1024 / 1024);
        fPruneMode = true;
    }

#ifdef ENABLE_WALLET
    bool fDisableWallet = GetBoolArg("-disablewallet", false); // 7.禁用钱包选项，默认关闭
#endif

    nConnectTimeout = GetArg("-timeout", DEFAULT_CONNECT_TIMEOUT); // 8.连接超时，默认 5000
    if (nConnectTimeout <= 0)
        nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;

    // Fee-per-kilobyte amount considered the same as "free" // 9.每千字节的交易费被视为与“免费”相同
    // If you are mining, be careful setting this: // 如果你正在挖矿，小心设置该选项：
    // if you set it to zero then // 如果你设置该值为 0
    // a transaction spammer can cheaply fill blocks using // 一个粉尘交易发送者可以轻松使用 1 satoshi 交易费的交易来填充块。
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction. // 该值应该设置为处理交易的成本之上。
    if (mapArgs.count("-minrelaytxfee")) // 最低中继交易费选项
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
    if (mapArgs.count("-mintxfee")) // 最低交易费选项
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
    if (mapArgs.count("-paytxfee")) // 交易费选项
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
    if (mapArgs.count("-maxtxfee")) // 最高交易费选项
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

    std::string strWalletFile = GetArg("-wallet", "wallet.dat"); // 指定的钱包文件名，默认为 "wallet.dat"
#endif // ENABLE_WALLET

    fIsBareMultisigStd = GetBoolArg("-permitbaremultisig", DEFAULT_PERMIT_BAREMULTISIG);
    fAcceptDatacarrier = GetBoolArg("-datacarrier", DEFAULT_ACCEPT_DATACARRIER);
    nMaxDatacarrierBytes = GetArg("-datacarriersize", nMaxDatacarrierBytes);

    fAlerts = GetBoolArg("-alerts", DEFAULT_ALERTS); // 转发选项，默认关闭

    // Option to startup with mocktime set (used for regression testing): // 选择使用 mocktime 设置启动（用于回归测试）：
    SetMockTime(GetArg("-mocktime", 0)); // SetMockTime(0) is a no-op // SetMockTime(0) 表示无操作

    if (GetBoolArg("-peerbloomfilters", true))
        nLocalServices |= NODE_BLOOM;

    fEnableReplacement = GetBoolArg("-mempoolreplacement", DEFAULT_ENABLE_REPLACEMENT);
    if ((!fEnableReplacement) && mapArgs.count("-mempoolreplacement")) {
        // Minimal effort at forwards compatibility // 向前兼容性的最小努力
        std::string strReplacementModeList = GetArg("-mempoolreplacement", "");  // default is impossible // 默认是不可能
        std::vector<std::string> vstrReplacementModes;
        boost::split(vstrReplacementModes, strReplacementModeList, boost::is_any_of(","));
        fEnableReplacement = (std::find(vstrReplacementModes.begin(), vstrReplacementModes.end(), "fee") != vstrReplacementModes.end());
    }

    // ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log // 初始化 ECC，目录锁检查（保证只有一个 bitcoind 运行），pid 文件，debug 日志

    // Initialize elliptic curve code // 1.初始化椭圆曲线代码
    ECC_Start(); // 椭圆曲线编码启动
    globalVerifyHandle.reset(new ECCVerifyHandle()); // 创建椭圆曲线验证对象

    // Sanity check // 2.完整性检查
    if (!InitSanityCheck()) // 初始化完整性检查 pending
        return InitError(_("Initialization sanity check failed. Bitcoin Core is shutting down."));

    std::string strDataDir = GetDataDir().string(); // 3.1.获取数据目录路径
#ifdef ENABLE_WALLET // 若开启钱包功能
    // Wallet file must be a plain filename without a directory // 3.2.钱包文件必须是不带目录的文件名
    if (strWalletFile != boost::filesystem::basename(strWalletFile) + boost::filesystem::extension(strWalletFile)) // 验证钱包文件名的完整性，basename 获取文件基础名 "wallet"，extension 获取文件扩展名 ".dat"
        return InitError(strprintf(_("Wallet %s resides outside data directory %s"), strWalletFile, strDataDir));
#endif // 钱包名校验结束
    // Make sure only a single Bitcoin process is using the data directory. // 3.3.确保只有一个比特币进程使用该数据目录。
    boost::filesystem::path pathLockFile = GetDataDir() / ".lock"; // 空的 lock 隐藏文件，作用：作为临界资源，保证当前只有一个 Bitcoin 进程使用数据目录
    FILE* file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file) fclose(file); // 若文件正常打开则关闭该空文件

    try {
        static boost::interprocess::file_lock lock(pathLockFile.string().c_str()); // 初始化文件锁对象
        if (!lock.try_lock()) // 上锁
            return InitError(strprintf(_("Cannot obtain a lock on data directory %s. Bitcoin Core is probably already running."), strDataDir)); // 第二个进程会在这里上锁失败并退出
    } catch(const boost::interprocess::interprocess_exception& e) {
        return InitError(strprintf(_("Cannot obtain a lock on data directory %s. Bitcoin Core is probably already running.") + " %s.", strDataDir, e.what()));
    }

#ifndef WIN32
    CreatePidFile(GetPidFile(), getpid()); // 4.非 win32 环境下，创建 pid 文件（记录当前 bitcoind 的进程号）
#endif
    if (GetBoolArg("-shrinkdebugfile", !fDebug)) // 5.若收缩调试文件选项开启
        ShrinkDebugFile(); // 5.1.收缩调试日志文件

    if (fPrintToDebugLog) // 打印到调试日志标志，默认打开
        OpenDebugLog(); // 5.2.打开调试日志文件

#ifdef ENABLE_WALLET
    LogPrintf("Using BerkeleyDB version %s\n", DbEnv::version(0, 0, 0)); // 6.钱包使用 BerkeleyDB
#endif
    if (!fLogTimestamps) // 时间戳标志，默认开启
        LogPrintf("Startup time: %s\n", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime())); // 记录启动时间
    LogPrintf("Default data directory %s\n", GetDefaultDataDir().string()); // 记录默认数据目录
    LogPrintf("Using data directory %s\n", strDataDir); // 记录当前指定使用的数据目录
    LogPrintf("Using config file %s\n", GetConfigFile().string()); // 记录使用的配置文件
    LogPrintf("Using at most %i connections (%i file descriptors available)\n", nMaxConnections, nFD); // 记录最大连接数（可用的文件描述符数量）
    std::ostringstream strErrors; // 错误信息的字符串输出流

    LogPrintf("Using %u threads for script verification\n", nScriptCheckThreads); // 记录脚本验证线程数（默认为 CPU 核数）
    if (nScriptCheckThreads) { // 7.创建 N-1 个脚本验证线程
        for (int i=0; i<nScriptCheckThreads-1; i++)
            threadGroup.create_thread(&ThreadScriptCheck); // CCheckQueue 类中的 loop 成员函数
    }

    // Start the lightweight task scheduler thread // 8.启动轻量级任务调度线程
    CScheduler::Function serviceLoop = boost::bind(&CScheduler::serviceQueue, &scheduler); // 8.1.Function/bind 绑定类成员函数 serviceQueue 到函数对象 serviceLoop
    threadGroup.create_thread(boost::bind(&TraceThread<CScheduler::Function>, "scheduler", serviceLoop)); // 8.2.线程组 threadGroup 创建一个轻量级任务调度线程

    /* Start the RPC server already.  It will be started in "warmup" mode
     * and not really process calls already (but it will signify connections
     * that the server is there and will be ready later).  Warmup mode will
     * be disabled when initialisation is finished.
     */ // 9.已经启动 RPC 服务。将以“预热”模式启动，而非已经真正地开始处理调用（但它表示服务器的连接并在之后准备好）。初始化完成后预热模式将被关闭。
    if (fServer) // 服务标志，默认打开，-server 选项，为 -cli 提供服务
    {
        uiInterface.InitMessage.connect(SetRPCWarmupStatus); // 9.1.注册/连接 设置 RPC 预热状态函数
        if (!AppInitServers(threadGroup)) // 9.2.应用程序初始化服务（启动 HTTP、RPC 相关服务）
            return InitError(_("Unable to start HTTP server. See debug log for details."));
    }

    int64_t nStart; // 启动标志

    // ********************************************************* Step 5: verify wallet database integrity // 验证钱包数据库的完整性
#ifdef ENABLE_WALLET // 前提，ENABLE_WALLET 在 bitcoin-config.h 中定义，通过 ./configure --disable-wallet 来禁用钱包
    if (!fDisableWallet) { // 禁止钱包标志，默认关闭，即默认打开钱包功能
        LogPrintf("Using wallet %s\n", strWalletFile); // 记录钱包文件名（指定/默认）
        uiInterface.InitMessage(_("Verifying wallet...")); // UI 交互，初始化钱包信息

        std::string warningString; // 警告信息
        std::string errorString; // 错误信息

        if (!CWallet::Verify(strWalletFile, warningString, errorString)) // 验证钱包数据库
            return false;

        if (!warningString.empty()) // 警告信息非空
            InitWarning(warningString);
        if (!errorString.empty()) // 错误信息非空
            return InitError(errorString);

    } // (!fDisableWallet)
#endif // ENABLE_WALLET
    // ********************************************************* Step 6: network initialization // 网络初始化

    RegisterNodeSignals(GetNodeSignals()); // 1.注册节点信号，获取节点信号全局对象，传入进行注册

    // sanitize comments per BIP-0014, format user agent and check total size // 根据 BIP-0014 清理评论，格式化用户代理并检查总大小
    std::vector<string> uacomments; // 2.存放用户代理评论列表
    BOOST_FOREACH(string cmt, mapMultiArgs["-uacomment"]) // 依次遍历所有评论
    {
        if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT)) // 序列化字符串后进行比较，保证不含不安全的字符
            return InitError(strprintf(_("User Agent comment (%s) contains unsafe characters."), cmt));
        uacomments.push_back(SanitizeString(cmt, SAFE_CHARS_UA_COMMENT)); // 加入评论列表
    }
    strSubVersion = FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments); // 6.3.获取客户子版本信息
    if (strSubVersion.size() > MAX_SUBVERSION_LENGTH) { // 版本信息不得超过 256 个字节
        return InitError(strprintf(_("Total length of network version string (%i) exceeds maximum length (%i). Reduce the number or size of uacomments."),
            strSubVersion.size(), MAX_SUBVERSION_LENGTH));
    }

    if (mapArgs.count("-onlynet")) { // 3.指定网络选项，只连接到指定网络中的节点
        std::set<enum Network> nets; // 存放指定网络的集合
        BOOST_FOREACH(const std::string& snet, mapMultiArgs["-onlynet"]) { // 遍历 -onlynet 的所有值
            enum Network net = ParseNetwork(snet); // 解析网络
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet));
            nets.insert(net); // 放入指定网络的集合
        }
        for (int n = 0; n < NET_MAX; n++) { // 遍历网络类型，共 5 种
            enum Network net = (enum Network)n;
            if (!nets.count(net)) // 若该网络类型未指定
                SetLimited(net); // 禁用未指定的网络类型
        }
    }

    if (mapArgs.count("-whitelist")) { // 4.白名单选项
        BOOST_FOREACH(const std::string& net, mapMultiArgs["-whitelist"]) { // 遍历指定的白名单列表
            CSubNet subnet(net); // 构建子网对象
            if (!subnet.IsValid()) // 检测子网是否有效
                return InitError(strprintf(_("Invalid netmask specified in -whitelist: '%s'"), net));
            CNode::AddWhitelistedRange(subnet); // 把有效的子网加入白名单列表
        }
    }

    bool proxyRandomize = GetBoolArg("-proxyrandomize", DEFAULT_PROXYRANDOMIZE); // 5.代理随机化选项，默认开启
    // -proxy sets a proxy for all outgoing network traffic // -proxy 设置全部向外网络流量的代理
    // -noproxy (or -proxy=0) as well as the empty string can be used to not set a proxy, this is the default // -noproxy（或 -proxy=0）以及空字符串用于不设置代理，这是默认值
    std::string proxyArg = GetArg("-proxy", ""); // 代理选项，指定代理地址，默认为 ""
    if (proxyArg != "" && proxyArg != "0") { // 值非 0 且 非空表示设置了代理
        proxyType addrProxy = proxyType(CService(proxyArg, 9050), proxyRandomize); // 设置代理地址和端口，端口默认为 9050
        if (!addrProxy.IsValid()) // 验证代理地址的有效性
            return InitError(strprintf(_("Invalid -proxy address: '%s'"), proxyArg));

        SetProxy(NET_IPV4, addrProxy); // 设置 IPV4 代理
        SetProxy(NET_IPV6, addrProxy); // 设置 IPV6 代理
        SetProxy(NET_TOR, addrProxy); // 设置 TOR 洋葱路由代理
        SetNameProxy(addrProxy); // 设置名字代理
        SetReachable(NET_TOR); // by default, -proxy sets onion as reachable, unless -noonion later
    }

    // -onion can be used to set only a proxy for .onion, or override normal proxy for .onion addresses // -onion 选项用于仅为 .onion 设置代理，或覆盖 .onion 地址的普通代理
    // -noonion (or -onion=0) disables connecting to .onion entirely // -noonion（或 -onion=0）完全关闭连接到 .onion
    // An empty string is used to not override the onion proxy (in which case it defaults to -proxy set above, or none) // 空字符串用于不覆盖洋葱代理（在此情况下，默认 -proxy 设置上面，或无）
    std::string onionArg = GetArg("-onion", ""); // 洋葱路由选项，默认关闭
    if (onionArg != "") { // 值非空时
        if (onionArg == "0") { // Handle -noonion/-onion=0
            SetReachable(NET_TOR, false); // set onions as unreachable
        } else { // 设置洋葱路由
            proxyType addrOnion = proxyType(CService(onionArg, 9050), proxyRandomize); // 设置洋葱路由地址和端口
            if (!addrOnion.IsValid()) // 检测洋葱路由地址可用性
                return InitError(strprintf(_("Invalid -onion address: '%s'"), onionArg));
            SetProxy(NET_TOR, addrOnion); // 设置洋葱代理
            SetReachable(NET_TOR); // 设置洋葱网络可达
        }
    }

    // see Step 2: parameter interactions for more information about these // 6.获取更多相关信息，查看第二步：参数交互
    fListen = GetBoolArg("-listen", DEFAULT_LISTEN); // 监听选项，默认开启
    fDiscover = GetBoolArg("-discover", true); // 发现选项，默认开启
    fNameLookup = GetBoolArg("-dns", DEFAULT_NAME_LOOKUP); // dns 名字发现，默认打开

    bool fBound = false; // 绑定状态，初始化为 false
    if (fListen) { // 默认 true
        if (mapArgs.count("-bind") || mapArgs.count("-whitebind")) { // 指定了 -bind 选项或 -whitebind
            BOOST_FOREACH(const std::string& strBind, mapMultiArgs["-bind"]) { // 遍历 bind 地址
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false)) // 解析 bind 地址
                    return InitError(strprintf(_("Cannot resolve -bind address: '%s'"), strBind));
                fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR)); // bind 绑定指定地址
            }
            BOOST_FOREACH(const std::string& strBind, mapMultiArgs["-whitebind"]) { // 遍历待绑定的白名单
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, 0, false))
                    return InitError(strprintf(_("Cannot resolve -whitebind address: '%s'"), strBind));
                if (addrBind.GetPort() == 0)
                    return InitError(strprintf(_("Need to specify a port with -whitebind: '%s'"), strBind));
                fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR | BF_WHITELIST));
            }
        }
        else { // 未设置 bind
            struct in_addr inaddr_any;
            inaddr_any.s_addr = INADDR_ANY; // 则绑定任意地址类型
            fBound |= Bind(CService(in6addr_any, GetListenPort()), BF_NONE); // 绑定本地 ipv6
            fBound |= Bind(CService(inaddr_any, GetListenPort()), !fBound ? BF_REPORT_ERROR : BF_NONE); // 绑定本地 ipv4，0.0.0.0:port 表示所有地址 或 任意地址
        }
        if (!fBound) // !false 绑定失败，记录错误日志并退出
            return InitError(_("Failed to listen on any port. Use -listen=0 if you want this."));
    }

    if (mapArgs.count("-externalip")) { // 外部的 ip 地址选项
        BOOST_FOREACH(const std::string& strAddr, mapMultiArgs["-externalip"]) { // 遍历指定的外部 ip 地址
            CService addrLocal(strAddr, GetListenPort(), fNameLookup); // 创建一个连接（地址和端口）对象
            if (!addrLocal.IsValid()) // 验证地址有效性
                return InitError(strprintf(_("Cannot resolve -externalip address: '%s'"), strAddr));
            AddLocal(CService(strAddr, GetListenPort(), fNameLookup), LOCAL_MANUAL); // 添加到本地主机映射列表
        }
    }

    BOOST_FOREACH(const std::string& strDest, mapMultiArgs["-seednode"]) // 遍历添加的种子节点 IP 地址
        AddOneShot(strDest); // 加入双端队列 vOneShots

#if ENABLE_ZMQ // 7.开启 ZeroMQ 选项，一套嵌入式的网络链接库，类似于 Socket 的一系列接口
    pzmqNotificationInterface = CZMQNotificationInterface::CreateWithArguments(mapArgs); // 初始化

    if (pzmqNotificationInterface) {
        RegisterValidationInterface(pzmqNotificationInterface); // 注册 zmq 通知接口
    }
#endif
    if (mapArgs.count("-maxuploadtarget")) { // 8.尝试保持外接流量低于给定目标值
        CNode::SetMaxOutboundTarget(GetArg("-maxuploadtarget", DEFAULT_MAX_UPLOAD_TARGET)*1024*1024); // 默认为 0 表示无限制
    }

    // ********************************************************* Step 7: load block chain // 加载区块链数据（区块数据目录 .bitcoin/blocks/）

    fReindex = GetBoolArg("-reindex", false); // 再索引标志（重新生成 rev 文件），默认关闭

    // Upgrading to 0.8; hard-link the old blknnnn.dat files into /blocks/ // 1.升级到 0.8；硬链接旧的区块数据文件 blknnnn.dat 到 /blocks/ 目录下
    boost::filesystem::path blocksDir = GetDataDir() / "blocks"; // 兼容老版的区块格式，区块文件扩容
    if (!boost::filesystem::exists(blocksDir)) // 若该目录不存在
    {
        boost::filesystem::create_directories(blocksDir); // 则创建区块数据目录
        bool linked = false;
        for (unsigned int i = 1; i < 10000; i++) { // 遍历原区块数据文件
            boost::filesystem::path source = GetDataDir() / strprintf("blk%04u.dat", i); // 旧版区块数据文件名
            if (!boost::filesystem::exists(source)) break;
            boost::filesystem::path dest = blocksDir / strprintf("blk%05u.dat", i-1); // 新版区块数据文件名，统一放在 blocks 目录下
            try {
                boost::filesystem::create_hard_link(source, dest); // 若存在旧版区块数据文件，则建立硬链接，以兼容新版
                LogPrintf("Hardlinked %s -> %s\n", source.string(), dest.string());
                linked = true; // 将链接标志设置为 true
            } catch (const boost::filesystem::filesystem_error& e) {
                // Note: hardlink creation failing is not a disaster, it just means
                // blocks will get re-downloaded from peers.
                LogPrintf("Error hardlinking blk%04u.dat: %s\n", i, e.what());
                break;
            }
        }
        if (linked) // 若建立了硬链接，则设置再索引标志为 true
        {
            fReindex = true;
        }
    }

    // cache size calculations // 2.缓存大小计算
    int64_t nTotalCache = (GetArg("-dbcache", nDefaultDbCache) << 20); // 总缓存大小
    nTotalCache = std::max(nTotalCache, nMinDbCache << 20); // total cache cannot be less than nMinDbCache // 总缓存不能低于 nMinDbCache
    nTotalCache = std::min(nTotalCache, nMaxDbCache << 20); // total cache cannot be greated than nMaxDbcache // 总缓存不能高于 nMaxDbcache
    int64_t nBlockTreeDBCache = nTotalCache / 8; // 区块树数据库缓存大小
    if (nBlockTreeDBCache > (1 << 21) && !GetBoolArg("-txindex", DEFAULT_TXINDEX))
        nBlockTreeDBCache = (1 << 21); // block tree db cache shouldn't be larger than 2 MiB
    nTotalCache -= nBlockTreeDBCache;
    int64_t nCoinDBCache = std::min(nTotalCache / 2, (nTotalCache / 4) + (1 << 23)); // use 25%-50% of the remainder for disk cache // 币数据库缓存大小
    nTotalCache -= nCoinDBCache;
    nCoinCacheUsage = nTotalCache; // the rest goes to in-memory cache // 比缓存用量
    LogPrintf("Cache configuration:\n");
    LogPrintf("* Using %.1fMiB for block index database\n", nBlockTreeDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for chain state database\n", nCoinDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for in-memory UTXO set\n", nCoinCacheUsage * (1.0 / 1024 / 1024));

    bool fLoaded = false; // 加载标志，表示加载区块索引是否成功，初始为 false
    while (!fLoaded) { // 3.若第一次没有加载成功，再加载一遍
        bool fReset = fReindex;
        std::string strLoadError;

        uiInterface.InitMessage(_("Loading block index..."));

        nStart = GetTimeMillis();
        do {
            try {
                UnloadBlockIndex(); // 为防第二次加载，先清空当前的区块索引
                delete pcoinsTip;
                delete pcoinsdbview;
                delete pcoinscatcher;
                delete pblocktree;

                pblocktree = new CBlockTreeDB(nBlockTreeDBCache, false, fReindex); // 区块索引
                pcoinsdbview = new CCoinsViewDB(nCoinDBCache, false, fReindex);
                pcoinscatcher = new CCoinsViewErrorCatcher(pcoinsdbview);
                pcoinsTip = new CCoinsViewCache(pcoinscatcher);

                if (fReindex) { // 默认 false
                    pblocktree->WriteReindexing(true); // 3.1.写入再索引标志为 true（区块数据库 leveldb）
                    //If we're reindexing in prune mode, wipe away unusable block files and all undo data files
                    if (fPruneMode) // 如果我们在修剪模式（修剪已确认的区块）下进行再索引，
                        CleanupBlockRevFiles(); // 清空无用的块文件（blk）和所有恢复数据文件（rev）
                }

                if (!LoadBlockIndex()) { // 3.2.从磁盘加载区块索引树和币数据库
                    strLoadError = _("Error loading block database");
                    break;
                }

                // If the loaded chain has a wrong genesis, bail out immediately // 如果加载的链的创世区块错误，马上补救
                // (we're likely using a testnet datadir, or the other way around). // （我们可能使用测试网的数据目录，或者相反）。
                if (!mapBlockIndex.empty() && mapBlockIndex.count(chainparams.GetConsensus().hashGenesisBlock) == 0) // 检查 mapBlockIndex 是否为空，且是否加载了创世区块索引（通过哈希查找）
                    return InitError(_("Incorrect or no genesis block found. Wrong datadir for network?"));

                // Initialize the block index (no-op if non-empty database was already loaded) // 初始化区块索引(如果非空数据库已经加载则无操作)
                if (!InitBlockIndex(chainparams)) { // 3.3.初始化区块索引到磁盘
                    strLoadError = _("Error initializing block database");
                    break;
                }

                // Check for changed -txindex state // 检查 -txindex 改变的状态
                if (fTxIndex != GetBoolArg("-txindex", DEFAULT_TXINDEX)) { // 检查 fTxIndex 标志，在 LoadBlockIndex 函数中可能被改变
                    strLoadError = _("You need to rebuild the database using -reindex to change -txindex");
                    break;
                }

                // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks // 检查 -prune 改变的状态。我们关注的时过去曾修剪过的区块，
                // in the past, but is now trying to run unpruned. // 但现在尝试运行未修剪过的区块。
                if (fHavePruned && !fPruneMode) { // 检查 fHavePruned 标志，用户删了一些文件后，又先在未修剪模式中运行 
                    strLoadError = _("You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain");
                    break;
                }

                uiInterface.InitMessage(_("Verifying blocks...")); // 开始验证区块
                if (fHavePruned && GetArg("-checkblocks", DEFAULT_CHECKBLOCKS) > MIN_BLOCKS_TO_KEEP) { // pending
                    LogPrintf("Prune: pruned datadir may not have more than %d blocks; -checkblocks=%d may fail\n",
                        MIN_BLOCKS_TO_KEEP, GetArg("-checkblocks", DEFAULT_CHECKBLOCKS));
                }

                {
                    LOCK(cs_main);
                    CBlockIndex* tip = chainActive.Tip(); // 获取激活的链尖区块索引
                    if (tip && tip->nTime > GetAdjustedTime() + 2 * 60 * 60) { // 链尖区块时间不能比当前时间快 2h
                        strLoadError = _("The block database contains a block which appears to be from the future. "
                                "This may be due to your computer's date and time being set incorrectly. "
                                "Only rebuild the block database if you are sure that your computer's date and time are correct");
                        break;
                    }
                }

                if (!CVerifyDB().VerifyDB(chainparams, pcoinsdbview, GetArg("-checklevel", DEFAULT_CHECKLEVEL),
                              GetArg("-checkblocks", DEFAULT_CHECKBLOCKS))) { // 验证数据库，验证等级默认 3，验证块数默认 288
                    strLoadError = _("Corrupted block database detected");
                    break;
                }
            } catch (const std::exception& e) {
                if (fDebug) LogPrintf("%s\n", e.what());
                strLoadError = _("Error opening block database");
                break;
            }

            fLoaded = true; // 加载成功
        } while(false);

        if (!fLoaded) { // 3.4.若加载失败
            // first suggest a reindex // 首次建议再索引
            if (!fReset) { // =fReindex
                bool fRet = uiInterface.ThreadSafeMessageBox(
                    strLoadError + ".\n\n" + _("Do you want to rebuild the block database now?"),
                    "", CClientUIInterface::MSG_ERROR | CClientUIInterface::BTN_ABORT); // 弹出交互框，针对 qt
                if (fRet) {
                    fReindex = true; // 再索引标志置为 true，下次再加载区块索引
                    fRequestShutdown = false; // 请求关闭标志置为 false
                } else {
                    LogPrintf("Aborted block database rebuild. Exiting.\n");
                    return false;
                }
            } else {
                return InitError(strLoadError);
            }
        }
    } // end of while load

    // As LoadBlockIndex can take several minutes, it's possible the user // LoadBlockIndex 会花几分钟，在最后一次操作期间，用户可能请求关闭 GUI。
    // requested to kill the GUI during the last operation. If so, exit. // 如此，便退出。
    // As the program has not fully started yet, Shutdown() is possibly overkill. // 问题是还未完全启动，Shutdown() 可能杀伤力过大。
    if (fRequestShutdown) // 若用户在加载区块期间请求关闭
    {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false; // 不调用 Shutdown() 直接退出
    }
    LogPrintf(" block index %15dms\n", GetTimeMillis() - nStart); // 记录区块索引时间

    boost::filesystem::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME; // 拼接费用估计文件路径
    CAutoFile est_filein(fopen(est_path.string().c_str(), "rb"), SER_DISK, CLIENT_VERSION); // 打开（首次创建）该文件并创建估费文件对象
    // Allowed to fail as this file IS missing on first startup. // 允许失败，因为首次启动时该文件不存在。
    if (!est_filein.IsNull()) // 若该文件存在
        mempool.ReadFeeEstimates(est_filein); // 内存池读取估计费用
    fFeeEstimatesInitialized = true; // 费用估计初始化状态标志置为 true

    // ********************************************************* Step 8: load wallet // 若启用钱包功能，则加载钱包
#ifdef ENABLE_WALLET // 1.钱包有效的宏
    if (fDisableWallet) { // 默认 false
        pwalletMain = NULL; // 钱包指针置空
        LogPrintf("Wallet disabled!\n");
    } else {

        // needed to restore wallet transaction meta data after -zapwallettxes // 需要在 -zapwallettxes 后恢复钱包交易元数据
        std::vector<CWalletTx> vWtx; // 钱包交易列表

        if (GetBoolArg("-zapwallettxes", false)) { // 分离钱包交易选项，默认关闭
            uiInterface.InitMessage(_("Zapping all transactions from wallet..."));

            pwalletMain = new CWallet(strWalletFile); // 1.1.创建并初始化钱包对象
            DBErrors nZapWalletRet = pwalletMain->ZapWalletTx(vWtx); // 从钱包中分离所有交易到钱包交易列表
            if (nZapWalletRet != DB_LOAD_OK) {
                uiInterface.InitMessage(_("Error loading wallet.dat: Wallet corrupted"));
                return false;
            }

            delete pwalletMain; // 删除钱包对象
            pwalletMain = NULL; // 指针置空
        }

        uiInterface.InitMessage(_("Loading wallet...")); // 开始加载钱包

        nStart = GetTimeMillis(); // 获取当前时间
        bool fFirstRun = true; // 首次运行标志，初始为 true
        pwalletMain = new CWallet(strWalletFile); // 1.2.创建新的钱包对象
        DBErrors nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun); // 加载钱包到内存（键值对）
        if (nLoadWalletRet != DB_LOAD_OK) // 加载钱包状态错误
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
        } // 加载钱包成功

        if (GetBoolArg("-upgradewallet", fFirstRun)) // 1.3.升级钱包选项，首次运行标志在这里应该为 false
        {
            int nMaxVersion = GetArg("-upgradewallet", 0);
            if (nMaxVersion == 0) // the -upgradewallet without argument case
            {
                LogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST); // 60000
                nMaxVersion = CLIENT_VERSION; // 最大版本为当前客户端版本
                pwalletMain->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately // 这里设置的是最小版本
            }
            else
                LogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
            if (nMaxVersion < pwalletMain->GetVersion()) // 若最大版本小于当前钱包版本
                strErrors << _("Cannot downgrade wallet") << "\n";
            pwalletMain->SetMaxVersion(nMaxVersion); // 设置最大版本
        }

        if (fFirstRun) // 1.4.若是首次运行
        {
            // Create new keyUser and set as default key // 创建新用户密钥并设置为默认密钥
            RandAddSeedPerfmon(); // 随机数种子

            CPubKey newDefaultKey; // 新公钥对象
            if (pwalletMain->GetKeyFromPool(newDefaultKey)) { // 从钥匙池取一个公钥
                pwalletMain->SetDefaultKey(newDefaultKey); // 设置该公钥为默认公钥
                if (!pwalletMain->SetAddressBook(pwalletMain->vchDefaultKey.GetID(), "", "receive")) // 设置默认公钥到地址簿默认账户 "" 下，并设置目的为接收
                    strErrors << _("Cannot write default address") << "\n";
            }

            pwalletMain->SetBestChain(chainActive.GetLocator()); // 主钱包设置最佳链，记录最佳块的位置
        }

        LogPrintf("%s", strErrors.str());
        LogPrintf(" wallet      %15dms\n", GetTimeMillis() - nStart); // 记录钱包加载的时间

        RegisterValidationInterface(pwalletMain); // 注册一个钱包用于接收 bitcoin core 的升级

        CBlockIndex *pindexRescan = chainActive.Tip(); // 获取链尖区块索引
        if (GetBoolArg("-rescan", false)) // 1.5.再扫描选项，默认关闭
            pindexRescan = chainActive.Genesis(); // 获取当前链的创世区块索引
        else
        {
            CWalletDB walletdb(strWalletFile); // 通过钱包文件名创建钱包数据库对象
            CBlockLocator locator;
            if (walletdb.ReadBestBlock(locator)) // 获取最佳区块的位置
                pindexRescan = FindForkInGlobalIndex(chainActive, locator); // 在激活的链和最佳区块间找最新的一个公共块
            else
                pindexRescan = chainActive.Genesis();
        }
        if (chainActive.Tip() && chainActive.Tip() != pindexRescan) // 链尖非创世区块也非分叉区块
        {
            //We can't rescan beyond non-pruned blocks, stop and throw an error // 我们无法再扫描超出非修剪的区块，停止或抛出一个错误。
            //this might happen if a user uses a old wallet within a pruned node // 如果用户在已修剪节点中使用旧钱包或者在更长时间中运行的 -disablewallet，
            // or if he ran -disablewallet for a longer time, then decided to re-enable // 则可能发生这种情况。
            if (fPruneMode) // 修剪模式标志，默认为 false
            {
                CBlockIndex *block = chainActive.Tip(); // 获取激活的链尖区块索引
                while (block && block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA) && block->pprev->nTx > 0 && pindexRescan != block) // 找到 pindexRescan 所对应区块
                    block = block->pprev;

                if (pindexRescan != block)
                    return InitError(_("Prune: last wallet synchronisation goes beyond pruned data. You need to -reindex (download the whole blockchain again in case of pruned node)"));
            }

            uiInterface.InitMessage(_("Rescanning...")); // 开始再扫描
            LogPrintf("Rescanning last %i blocks (from block %i)...\n", chainActive.Height() - pindexRescan->nHeight, pindexRescan->nHeight); // 记录从 pindexRescan->nHeight 开始再扫描的区块个数
            nStart = GetTimeMillis(); // 记录再扫描的开始时间
            pwalletMain->ScanForWalletTransactions(pindexRescan, true); // 再扫描钱包交易
            LogPrintf(" rescan      %15dms\n", GetTimeMillis() - nStart); // 记录再扫描的用时
            pwalletMain->SetBestChain(chainActive.GetLocator()); // 设置最佳链（内存、数据库）
            nWalletDBUpdated++; // 钱包数据库升级次数加 1

            // Restore wallet transaction metadata after -zapwallettxes=1 // 在 zapwallettxes 选项设置模式 1 后，恢复钱包交易元数据
            if (GetBoolArg("-zapwallettxes", false) && GetArg("-zapwallettxes", "1") != "2")
            { // 该选项设置会删除所有钱包交易且只恢复在启动时通过使用 -rescan 再扫描选项的部分区块链（模式）
                CWalletDB walletdb(strWalletFile); // 创建钱包数据库对象

                BOOST_FOREACH(const CWalletTx& wtxOld, vWtx) // 遍历钱包交易列表
                {
                    uint256 hash = wtxOld.GetHash(); // 获取钱包交易哈希
                    std::map<uint256, CWalletTx>::iterator mi = pwalletMain->mapWallet.find(hash); // 在钱包映射交易映射列表中查找该交易
                    if (mi != pwalletMain->mapWallet.end()) // 若找到
                    { // 更新该笔钱包交易
                        const CWalletTx* copyFrom = &wtxOld;
                        CWalletTx* copyTo = &mi->second;
                        copyTo->mapValue = copyFrom->mapValue;
                        copyTo->vOrderForm = copyFrom->vOrderForm;
                        copyTo->nTimeReceived = copyFrom->nTimeReceived;
                        copyTo->nTimeSmart = copyFrom->nTimeSmart;
                        copyTo->fFromMe = copyFrom->fFromMe;
                        copyTo->strFromAccount = copyFrom->strFromAccount;
                        copyTo->nOrderPos = copyFrom->nOrderPos;
                        copyTo->WriteToDisk(&walletdb); // 写入钱包数据文件中
                    }
                }
            }
        }
        pwalletMain->SetBroadcastTransactions(GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST)); // 设置广播交易，默认为 true
    } // (!fDisableWallet)
#else // 2.!ENABLE_WALLET
    LogPrintf("No wallet support compiled in!\n");
#endif // !ENABLE_WALLET

    // ********************************************************* Step 9: data directory maintenance // 若是裁剪模式且关闭了再索引选项，则进行 blockstore 的裁剪

    // if pruning, unset the service bit and perform the initial blockstore prune // 如果正在修剪，
    // after any wallet rescanning has taken place. // 在任何钱包再扫描发生后，取消设置服务位并执行初始区块存储修剪。
    if (fPruneMode) { // 裁剪标志，默认为 false
        LogPrintf("Unsetting NODE_NETWORK on prune mode\n");
        nLocalServices &= ~NODE_NETWORK; // 取消设置本地服务中的 NODE_NETWORK
        if (!fReindex) { // 若再索引标志关闭
            uiInterface.InitMessage(_("Pruning blockstore...")); // 开始修剪区块存储
            PruneAndFlush(); // 设置修剪标志并刷新磁盘上的链状态
        }
    }

    // ********************************************************* Step 10: import blocks // 导入区块数据

    if (mapArgs.count("-blocknotify")) // 1.若注册了区块通知的命令
        uiInterface.NotifyBlockTip.connect(BlockNotifyCallback); // 连接区块通知回调函数

    uiInterface.InitMessage(_("Activating best chain..."));
    // scan for better chains in the block chain database, that are not yet connected in the active best chain // 扫描区块链数据库中的最佳链，这些链还没连接到激活的最佳链
    CValidationState state;
    if (!ActivateBestChain(state, chainparams)) // 2.激活最佳链，并获取验证状态
        strErrors << "Failed to connect best block";

    std::vector<boost::filesystem::path> vImportFiles; // 导入文件列表（存放导入区块文件的路径）
    if (mapArgs.count("-loadblock")) // 导入区块文件选项
    {
        BOOST_FOREACH(const std::string& strFile, mapMultiArgs["-loadblock"]) // 3.遍历指定的区块文件
            vImportFiles.push_back(strFile); // 放入文件列表
    }
    threadGroup.create_thread(boost::bind(&ThreadImport, vImportFiles)); // 4.创建一个用于导入区块线程
    if (chainActive.Tip() == NULL) { // 至少创世区块要加载完成
        LogPrintf("Waiting for genesis block to be imported...\n");
        while (!fRequestShutdown && chainActive.Tip() == NULL) // 必须保证至少加载创世区块
            MilliSleep(10); // 否则睡 10ms 等待导入区块线程完成工作
    }

    // ********************************************************* Step 11: start node // 启动节点服务，监听网络 P2P 请求，挖矿线程

    if (!CheckDiskSpace()) // 1.检测硬盘剩余空间是否充足（最少 50MB），用于接收并存储新区块
        return false; // 若空间不足，返回 false 退出

    if (!strErrors.str().empty()) // 2.检查前面的初始化过程是否有错误信息
        return InitError(strErrors.str()); // 若存在错误信息，返回错误信息并退出

    RandAddSeedPerfmon(); // 3.用于给钱包生成随机私钥种子

    //// debug print // 4.调试打印，记录相关信息
    LogPrintf("mapBlockIndex.size() = %u\n",   mapBlockIndex.size()); // 区块索引大小
    LogPrintf("nBestHeight = %d\n",                   chainActive.Height()); // 最佳区块链高度
#ifdef ENABLE_WALLET
    LogPrintf("setKeyPool.size() = %u\n",      pwalletMain ? pwalletMain->setKeyPool.size() : 0); // 钱包内密钥池大小
    LogPrintf("mapWallet.size() = %u\n",       pwalletMain ? pwalletMain->mapWallet.size() : 0); // 钱包交易列表大小
    LogPrintf("mapAddressBook.size() = %u\n",  pwalletMain ? pwalletMain->mapAddressBook.size() : 0); // 钱包内地址簿的大小
#endif

    if (GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION)) // 5.监听洋葱路由，默认打开
        StartTorControl(threadGroup, scheduler);

    StartNode(threadGroup, scheduler); // 6.启动各种线程

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

    // Generate coins in the background // 7.挖矿作用：产生比特币，记录交易
    GenerateBitcoins(GetBoolArg("-gen", DEFAULT_GENERATE), GetArg("-genproclimit", DEFAULT_GENERATE_THREADS), chainparams); // 创建挖矿线程，默认关闭，线程数默认为 1（0 表示禁止挖矿，-1 表示 CPU 核数）

    // ********************************************************* Step 12: finished // 完成

    SetRPCWarmupFinished(); // 设置 RPC 预热已完成
    uiInterface.InitMessage(_("Done loading")); // 提示加载完成信息

#ifdef ENABLE_WALLET
    if (pwalletMain) {
        // Add wallet transactions that aren't already in a block to mapTransactions
        pwalletMain->ReacceptWalletTransactions(); // 重新接收钱包交易，把钱包交易中的交易添加到内存池中

        // Run a thread to flush wallet periodically
        threadGroup.create_thread(boost::bind(&ThreadFlushWalletDB, boost::ref(pwalletMain->strWalletFile))); // 定期刷新钱包线程
    }
#endif

    return !fRequestShutdown;
}
