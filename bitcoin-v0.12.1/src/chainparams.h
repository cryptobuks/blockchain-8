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
    std::string name, host; // ������IP ��ַ
    CDNSSeedData(const std::string &strName, const std::string &strHost) : name(strName), host(strHost) {}
};

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

typedef std::map<int, uint256> MapCheckpoints; // map<����ţ��߶ȣ��� �����ϣ>

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
 */ // �� CChainParams �����˱��ر�ϵͳ����ʵ���ĸ��ֿɵ��ò����������֣����ǽ�����Ʒ�ͷ������������ʱ���õĹ����������ͽ���˽������Ļع����ģʽ������ȷ�������ҵ������С�Ѷȡ�
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

    const Consensus::Params& GetConsensus() const { return consensus; } // ��ȡ��ʶ
    const CMessageHeader::MessageStartChars& MessageStart() const { return pchMessageStart; } // ��ȡͨѶЭ����Ϣͷ
    const std::vector<unsigned char>& AlertKey() const { return vAlertPubKey; }
    int GetDefaultPort() const { return nDefaultPort; } // ��ȡĬ�϶˿ں�

    const CBlock& GenesisBlock() const { return genesis; } // ��ȡ��������
    /** Make miner wait to have peers to avoid wasting work */ // ʹ�󹤵ȴ�ͬ���ڵ��������˷ѹ���
    bool MiningRequiresPeers() const { return fMiningRequiresPeers; } // �����ڿ���ͬ���ڵ��־
    /** Default value for -checkmempool and -checkblockindex argument */
    bool DefaultConsistencyChecks() const { return fDefaultConsistencyChecks; }
    /** Policy: Filter transactions that do not match well-defined patterns */
    bool RequireStandard() const { return fRequireStandard; }
    int64_t MaxTipAge() const { return nMaxTipAge; }
    uint64_t PruneAfterHeight() const { return nPruneAfterHeight; }
    /** Make miner stop after a block is found. In RPC, don't return until nGenProcLimit blocks are generated */
    bool MineBlocksOnDemand() const { return fMineBlocksOnDemand; } // �����ڿ������־
    /** In the future use NetworkIDString() for RPC fields */ // �Ժ��� RPC ����ʹ�� NetworkIDString()
    bool TestnetToBeDeprecatedFieldRPC() const { return fTestnetToBeDeprecatedFieldRPC; }
    /** Return the BIP70 network string (main, test or regtest) */
    std::string NetworkIDString() const { return strNetworkID; } // ���� BIP70 ��������main, test �� regtest��
    const std::vector<CDNSSeedData>& DNSSeeds() const { return vSeeds; }
    const std::vector<unsigned char>& Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const std::vector<SeedSpec6>& FixedSeeds() const { return vFixedSeeds; }
    const CCheckpointData& Checkpoints() const { return checkpointData; }
protected:
    CChainParams() {}

    Consensus::Params consensus;
    CMessageHeader::MessageStartChars pchMessageStart; // ��Ϣħ��
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
    bool fMineBlocksOnDemand; // �ڿ������־��ֻ�лع��������Ϊ true
    bool fTestnetToBeDeprecatedFieldRPC;
    CCheckpointData checkpointData;
};

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */ // ���ص�ǰѡ��������������˵�Ԫ���ԣ���Ӧ�ó��������󲻻�ı䡣
const CChainParams &Params();

/**
 * @returns CChainParams for the given BIP70 chain name.
 */ // ���ػ��� BIP70 ������������
CChainParams& Params(const std::string& chain);

/**
 * Sets the params returned by Params() to those for the given BIP70 chain name.
 * @throws std::runtime_error when the chain is not supported.
 */ // �� Params() ���صĲ������õ������� BIP70 ������
void SelectParams(const std::string& chain);

#endif // BITCOIN_CHAINPARAMS_H
