// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMS_H
#define BITCOIN_CHAINPARAMS_H

#include "chainparamsbase.h"
#include "consensus/params.h"
#include "primitives/block.h"
#include "protocol.h"

#include <vector>

struct CDNSSeedData {
    std::string name, host; // 域名，IP 地址
    CDNSSeedData(const std::string &strName, const std::string &strHost) : name(strName), host(strHost) {}
};

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

typedef std::map<int, uint256> MapCheckpoints;

struct CCheckpointData {
    MapCheckpoints mapCheckpoints;
    int64_t nTimeLastCheckpoint;
    int64_t nTransactionsLastCheckpoint;
    double fTransactionsPerDay;
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */ // 类 CChainParams 定义了比特币系统给定实例的各种可调用参数。有三种：人们交易商品和服务的主网，不时重置的公共测试网和仅限私有网络的回归测试模式。它有确保立刻找到块的最小难度。
class CChainParams
{
public:
    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        MAX_BASE58_TYPES
    };

    const Consensus::Params& GetConsensus() const { return consensus; }
    const CMessageHeader::MessageStartChars& MessageStart() const { return pchMessageStart; } // 获取通讯协议消息头
    const std::vector<unsigned char>& AlertKey() const { return vAlertPubKey; }
    int GetDefaultPort() const { return nDefaultPort; } // 获取默认端口号

    const CBlock& GenesisBlock() const { return genesis; } // 获取创世区块
    /** Make miner wait to have peers to avoid wasting work */ // 使矿工等待同辈节点来避免浪费工作
    bool MiningRequiresPeers() const { return fMiningRequiresPeers; } // 返回挖矿需同辈节点标志
    /** Default value for -checkmempool and -checkblockindex argument */
    bool DefaultConsistencyChecks() const { return fDefaultConsistencyChecks; }
    /** Policy: Filter transactions that do not match well-defined patterns */
    bool RequireStandard() const { return fRequireStandard; }
    int64_t MaxTipAge() const { return nMaxTipAge; }
    uint64_t PruneAfterHeight() const { return nPruneAfterHeight; }
    /** Make miner stop after a block is found. In RPC, don't return until nGenProcLimit blocks are generated */
    bool MineBlocksOnDemand() const { return fMineBlocksOnDemand; } // 返回挖矿需求标志
    /** In the future use NetworkIDString() for RPC fields */ // 以后再 RPC 区域使用 NetworkIDString()
    bool TestnetToBeDeprecatedFieldRPC() const { return fTestnetToBeDeprecatedFieldRPC; }
    /** Return the BIP70 network string (main, test or regtest) */
    std::string NetworkIDString() const { return strNetworkID; } // 返回 BIP70 网络名（main, test 或 regtest）
    const std::vector<CDNSSeedData>& DNSSeeds() const { return vSeeds; }
    const std::vector<unsigned char>& Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const std::vector<SeedSpec6>& FixedSeeds() const { return vFixedSeeds; }
    const CCheckpointData& Checkpoints() const { return checkpointData; }
protected:
    CChainParams() {}

    Consensus::Params consensus;
    CMessageHeader::MessageStartChars pchMessageStart;
    //! Raw pub key bytes for the broadcast alert signing key.
    std::vector<unsigned char> vAlertPubKey;
    int nDefaultPort;
    long nMaxTipAge;
    uint64_t nPruneAfterHeight;
    std::vector<CDNSSeedData> vSeeds;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    std::string strNetworkID;
    CBlock genesis;
    std::vector<SeedSpec6> vFixedSeeds;
    bool fMiningRequiresPeers;
    bool fDefaultConsistencyChecks;
    bool fRequireStandard;
    bool fMineBlocksOnDemand; // 挖矿需求标志，只有回归测试网中为 true
    bool fTestnetToBeDeprecatedFieldRPC;
    CCheckpointData checkpointData;
};

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */ // 返回当前选择的链参数。除了单元测试，在应用程序启动后不会改变。
const CChainParams &Params();

/**
 * @returns CChainParams for the given BIP70 chain name.
 */ // 返回基于 BIP70 链名的链参数
CChainParams& Params(const std::string& chain);

/**
 * Sets the params returned by Params() to those for the given BIP70 chain name.
 * @throws std::runtime_error when the chain is not supported.
 */
void SelectParams(const std::string& chain);

#endif // BITCOIN_CHAINPARAMS_H
