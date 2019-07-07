// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "main.h"
#include "miner.h"
#include "net.h"
#include "pow.h"
#include "rpcserver.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validationinterface.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp>
#include <boost/shared_ptr.hpp>

#include <univalue.h>

using namespace std;

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is nonpositive.
 * If 'height' is nonnegative, compute the estimate at the time when a given block was found.
 */ // ���ػ������·��ֵĿ�ÿ���ƽ�������ϣ�����������Ƿ����򷵻����µ��Ѷȸı䡣���߶ȷǸ��������ҵ�һ����������ʱ�Ĺ���ֵ
UniValue GetNetworkHashPS(int lookup, int height) { // Ĭ�� (120, -1)
    CBlockIndex *pb = chainActive.Tip(); // ��ȡ������������

    if (height >= 0 && height < chainActive.Height()) // ��ָ���߶ȷ��ϵ�ǰ���߶ȷ�Χ
        pb = chainActive[height]; // ��ȡ��Ӧ�߶ȵ���������

    if (pb == NULL || !pb->nHeight) // ����Ϊ�� �� Ϊ������������
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup <= 0) // �������� -1����ʹ�ô��ϴ��Ѷȸı�������
        lookup = pb->nHeight % Params().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight) // �����ִ������߶ȣ�������Ϊ���߶�
        lookup = pb->nHeight;

    CBlockIndex *pb0 = pb;
    int64_t minTime = pb0->GetBlockTime(); // ��ȡ��С��������ʱ��
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime); // ��ȡ��󴴽�����ʱ��
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime) // ��С����������
        return 0;

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork; // ������β����Ĺ�����֮��
    int64_t timeDiff = maxTime - minTime; // ʱ���

    return workDiff.getdouble() / timeDiff; // ת��Ϊ��������ƽ��ֵ������
}

UniValue getnetworkhashps(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2) // �����������Ϊ 2 ��
        throw runtime_error( // �����������
            "getnetworkhashps ( blocks height )\n"
            "\nReturns the estimated network hashes per second based on the last n blocks.\n"
            "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
            "Pass in [height] to estimate the network speed at the time when a certain block was found.\n"
            "\nArguments:\n"
            "1. blocks     (numeric, optional, default=120) The number of blocks, or -1 for blocks since last difficulty change.\n"
            "2. height     (numeric, optional, default=-1) To estimate at the time of the given height.\n"
            "\nResult:\n"
            "x             (numeric) Hashes per second estimated\n"
            "\nExamples:\n"
            + HelpExampleCli("getnetworkhashps", "")
            + HelpExampleRpc("getnetworkhashps", "")
       );

    LOCK(cs_main);
    return GetNetworkHashPS(params.size() > 0 ? params[0].get_int() : 120, params.size() > 1 ? params[1].get_int() : -1); // ��ȡ������������ϣ����/�룩������
}

UniValue getgenerate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // û�в���
        throw runtime_error( // �����������
            "getgenerate\n"
            "\nReturn if the server is set to generate coins or not. The default is false.\n"
            "It is set with the command line argument -gen (or " + std::string(BITCOIN_CONF_FILENAME) + " setting gen)\n"
            "It can also be set with the setgenerate call.\n"
            "\nResult\n"
            "true|false      (boolean) If the server is set to generate coins or not\n"
            "\nExamples:\n"
            + HelpExampleCli("getgenerate", "")
            + HelpExampleRpc("getgenerate", "")
        );

    LOCK(cs_main);
    return GetBoolArg("-gen", DEFAULT_GENERATE); // ��ȡ "-gen" ѡ���ֵ������
}

UniValue generate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1) // 1.����ֻ��Ϊ 1 ����Ҫ��������ĸ�����
        throw runtime_error( // ������Ϣ����
            "generate numblocks\n"
            "\nMine blocks immediately (before the RPC call returns)\n"
            "\nNote: this function can only be used on the regtest network\n"
            "\nArguments:\n"
            "1. numblocks    (numeric, required) How many blocks are generated immediately.\n"
            "\nResult\n"
            "[ blockhashes ]     (array) hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks\n"
            + HelpExampleCli("generate", "11")
        );

    if (!Params().MineBlocksOnDemand()) // 2.������磬ֻ�лع���������� true
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "This method can only be used on regtest"); // ��ʾ

    int nHeightStart = 0; // ������ǰ�ĸ߶�
    int nHeightEnd = 0; // �������ĸ߶�
    int nHeight = 0; // ��ǰ�������߶�
    int nGenerate = params[0].get_int(); // 3.��ȡҪ�����������Ŀ

    boost::shared_ptr<CReserveScript> coinbaseScript; // 4.�������ҽ��׽ű�
    GetMainSignals().ScriptForMining(coinbaseScript);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbaseScript) // 5.����Կ�غľ����������᷵�ؽű���ץס����
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    //throw an error if no script was provided
    if (coinbaseScript->reserveScript.empty()) // 6.����ű�Ϊ�գ�δ���ṩ�����׳�һ������
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available (mining requires a wallet)");

    {   // Don't keep cs_main locked
        LOCK(cs_main); // ��С�����ķ�Χ
        nHeightStart = chainActive.Height(); // 7.��ȡ��ǰ�������߶�
        nHeight = nHeightStart; // ��¼��ǰ�߶�
        nHeightEnd = nHeightStart+nGenerate; // �õ�����ָ��������ĸ߶�
    }
    unsigned int nExtraNonce = 0;
    UniValue blockHashes(UniValue::VARR); // �������͵������ϣ����
    while (nHeight < nHeightEnd)
    { // 8.ѭ������ָ����Ŀ������
        auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(Params(), coinbaseScript->reserveScript)); // ��������ģ��
        if (!pblocktemplate.get()) // ��֤�Ƿ񴴽��ɹ�
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        CBlock *pblock = &pblocktemplate->block; // ��ȡ����ָ��
        {
            LOCK(cs_main);
            IncrementExtraNonce(pblock, chainActive.Tip(), nExtraNonce); // ���Ӷ���������
        }
        while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus())) { // ��������Ƿ����㹤����֤��
            // Yes, there is a chance every nonce could fail to satisfy the -regtest
            // target -- 1 in 2^(2^32). That ain't gonna happen. // ÿ����������п����޷����� -regtest Ŀ��ֵ -- 2^(2^32) ��֮ 1���ⲻ�ᷢ���ġ�
            ++pblock->nNonce; // ����ͷ��������� 1
        }
        CValidationState state;
        if (!ProcessNewBlock(state, Params(), NULL, pblock, true, NULL))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
        ++nHeight; // ���ӵ�ǰ�߶�
        blockHashes.push_back(pblock->GetHash().GetHex()); // ׷�������ϣ

        //mark script as important because it was used at least for one coinbase output
        coinbaseScript->KeepScript(); // ��Ǹýű�Ϊ��Ҫ����Ϊ����������һ���������
    }
    return blockHashes; // 9.���ز�����������Ĺ�ϣ
}

UniValue setgenerate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) // ��������Ϊ 1 ��������Ϊ 2 ��
        throw runtime_error( // �����������
            "setgenerate generate ( genproclimit )\n"
            "\nSet 'generate' true or false to turn generation on or off.\n"
            "Generation is limited to 'genproclimit' processors, -1 is unlimited.\n"
            "See the getgenerate call for the current setting.\n"
            "\nArguments:\n"
            "1. generate         (boolean, required) Set to true to turn on generation, off to turn off.\n"
            "2. genproclimit     (numeric, optional) Set the processor limit for when generation is on. Can be -1 for unlimited.\n"
            "\nExamples:\n"
            "\nSet the generation on with a limit of one processor\n"
            + HelpExampleCli("setgenerate", "true 1") +
            "\nCheck the setting\n"
            + HelpExampleCli("getgenerate", "") +
            "\nTurn off generation\n"
            + HelpExampleCli("setgenerate", "false") +
            "\nUsing json rpc\n"
            + HelpExampleRpc("setgenerate", "true, 1")
        );

    if (Params().MineBlocksOnDemand()) // ���ǻع�������磬�˷��������ã�ʹ�� "generate" ����
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Use the generate method instead of setgenerate on this network");

    bool fGenerate = true; // �ڿ󿪹ر�־
    if (params.size() > 0)
        fGenerate = params[0].get_bool(); // ��ȡָ�����ڿ�״̬

    int nGenProcLimit = GetArg("-genproclimit", DEFAULT_GENERATE_THREADS); // ��ʼ��Ĭ���ڿ��߳���
    if (params.size() > 1)
    {
        nGenProcLimit = params[1].get_int(); // ��ȡָ�����ڿ��߳���
        if (nGenProcLimit == 0) // ��ָ���߳���Ϊ 0
            fGenerate = false; // �ر��ڿ���
    }

    mapArgs["-gen"] = (fGenerate ? "1" : "0"); // �ı��ڿ�ѡ���ֵ
    mapArgs ["-genproclimit"] = itostr(nGenProcLimit); // �޸��ڿ��߳���
    GenerateBitcoins(fGenerate, nGenProcLimit, Params()); // ����ָ���������ڿ��߳�

    return NullUniValue; // ���ؿ�ֵ
}

UniValue getmininginfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0) // û�в���
        throw runtime_error( // �����������
            "getmininginfo\n"
            "\nReturns a json object containing mining-related information."
            "\nResult:\n"
            "{\n"
            "  \"blocks\": nnn,             (numeric) The current block\n"
            "  \"currentblocksize\": nnn,   (numeric) The last block size\n"
            "  \"currentblocktx\": nnn,     (numeric) The last block transaction\n"
            "  \"difficulty\": xxx.xxxxx    (numeric) The current difficulty\n"
            "  \"errors\": \"...\"          (string) Current errors\n"
            "  \"generate\": true|false     (boolean) If the generation is on or off (see getgenerate or setgenerate calls)\n"
            "  \"genproclimit\": n          (numeric) The processor limit for generation. -1 if no generation. (see getgenerate or setgenerate calls)\n"
            "  \"pooledtx\": n              (numeric) The size of the mem pool\n"
            "  \"testnet\": true|false      (boolean) If using testnet or not\n"
            "  \"chain\": \"xxxx\",         (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
        );


    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ); // �����������͵ķ��ؽ��
    obj.push_back(Pair("blocks",           (int)chainActive.Height())); // ���뼤������߶�
    obj.push_back(Pair("currentblocksize", (uint64_t)nLastBlockSize)); // ��������Ĵ�С
    obj.push_back(Pair("currentblocktx",   (uint64_t)nLastBlockTx)); // ��������Ľ�����
    obj.push_back(Pair("difficulty",       (double)GetDifficulty())); // ��ǰ�ڿ��Ѷ�
    obj.push_back(Pair("errors",           GetWarnings("statusbar"))); // ����
    obj.push_back(Pair("genproclimit",     (int)GetArg("-genproclimit", DEFAULT_GENERATE_THREADS))); // ���߳���
    obj.push_back(Pair("networkhashps",    getnetworkhashps(params, false))); // ȫ������
    obj.push_back(Pair("pooledtx",         (uint64_t)mempool.size())); // �����ڴ�ش�С
    obj.push_back(Pair("testnet",          Params().TestnetToBeDeprecatedFieldRPC())); // �Ƿ�Ϊ������
    obj.push_back(Pair("chain",            Params().NetworkIDString())); // ����
    obj.push_back(Pair("generate",         getgenerate(params, false))); // �ڿ�״̬
    return obj;
}


// NOTE: Unlike wallet RPC (which use BTC values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
UniValue prioritisetransaction(const UniValue& params, bool fHelp) // ע����Ǯ�� RPC ��ʹ�� BTC����ͬ���ڿ� RPC ʹ�� satoshi ��Ϊ��λ
{
    if (fHelp || params.size() != 3) // ����Ϊ 3 ������
        throw runtime_error( // �����������
            "prioritisetransaction <txid> <priority delta> <fee delta>\n"
            "Accepts the transaction into mined blocks at a higher (or lower) priority\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id.\n"
            "2. priority delta (numeric, required) The priority to add or subtract.\n"
            "                  The transaction selection algorithm considers the tx as it would have a higher priority.\n"
            "                  (priority of a transaction is calculated: coinage * value_in_satoshis / txsize) \n"
            "3. fee delta      (numeric, required) The fee value (in satoshis) to add (or subtract, if negative).\n"
            "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
            "                  considers the transaction as it would have paid a higher (or lower) fee.\n"
            "\nResult\n"
            "true              (boolean) Returns true\n"
            "\nExamples:\n"
            + HelpExampleCli("prioritisetransaction", "\"txid\" 0.0 10000")
            + HelpExampleRpc("prioritisetransaction", "\"txid\", 0.0, 10000")
        );

    LOCK(cs_main);

    uint256 hash = ParseHashStr(params[0].get_str(), "txid"); // ��ȡָ���Ľ��׹�ϣ������ uint256 ����
    CAmount nAmount = params[2].get_int64(); // ��ȡ���׽��

    mempool.PrioritiseTransaction(hash, params[0].get_str(), params[1].get_real(), nAmount); // ����ָ���������ȼ�
    return true;
}


// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state) // ע������һ��ȷ���Ľ�����������ǲ�ȷ���ģ������ɵ��÷�����
{
    if (state.IsValid()) // ��Ч״̬
        return NullUniValue; // ���ؿ�

    std::string strRejectReason = state.GetRejectReason(); // ��ȡ�ܾ�ԭ��
    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
    if (state.IsInvalid()) // ״̬��Ч
    {
        if (strRejectReason.empty()) // �ܾ�ԭ��Ϊ��
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?"; // Ӧ���ǲ����ܵ�
}

UniValue getblocktemplate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1) // �������Ϊ 1 ��
        throw runtime_error( // �����������
            "getblocktemplate ( \"jsonrequestobject\" )\n"
            "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
            "It returns data needed to construct a block to work on.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments:\n"
            "1. \"jsonrequestobject\"       (string, optional) A json object in the following spec\n"
            "     {\n"
            "       \"mode\":\"template\"    (string, optional) This must be set to \"template\" or omitted\n"
            "       \"capabilities\":[       (array, optional) A list of strings\n"
            "           \"support\"           (string) client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'\n"
            "           ,...\n"
            "         ]\n"
            "     }\n"
            "\n"

            "\nResult:\n"
            "{\n"
            "  \"version\" : n,                    (numeric) The block version\n"
            "  \"previousblockhash\" : \"xxxx\",    (string) The hash of current highest block\n"
            "  \"transactions\" : [                (array) contents of non-coinbase transactions that should be included in the next block\n"
            "      {\n"
            "         \"data\" : \"xxxx\",          (string) transaction data encoded in hexadecimal (byte-for-byte)\n"
            "         \"hash\" : \"xxxx\",          (string) hash/id encoded in little-endian hexadecimal\n"
            "         \"depends\" : [              (array) array of numbers \n"
            "             n                        (numeric) transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is\n"
            "             ,...\n"
            "         ],\n"
            "         \"fee\": n,                   (numeric) difference in value between transaction inputs and outputs (in Satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one\n"
            "         \"sigops\" : n,               (numeric) total number of SigOps, as counted for purposes of block limits; if key is not present, sigop count is unknown and clients MUST NOT assume there aren't any\n"
            "         \"required\" : true|false     (boolean) if provided and true, this transaction must be in the final block\n"
            "      }\n"
            "      ,...\n"
            "  ],\n"
            "  \"coinbaseaux\" : {                  (json object) data that should be included in the coinbase's scriptSig content\n"
            "      \"flags\" : \"flags\"            (string) \n"
            "  },\n"
            "  \"coinbasevalue\" : n,               (numeric) maximum allowable input to coinbase transaction, including the generation award and transaction fees (in Satoshis)\n"
            "  \"coinbasetxn\" : { ... },           (json object) information for coinbase transaction\n"
            "  \"target\" : \"xxxx\",               (string) The hash target\n"
            "  \"mintime\" : xxx,                   (numeric) The minimum timestamp appropriate for next block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mutable\" : [                      (array of string) list of ways the block template may be changed \n"
            "     \"value\"                         (string) A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'\n"
            "     ,...\n"
            "  ],\n"
            "  \"noncerange\" : \"00000000ffffffff\",   (string) A range of valid nonces\n"
            "  \"sigoplimit\" : n,                 (numeric) limit of sigops in blocks\n"
            "  \"sizelimit\" : n,                  (numeric) limit of block size\n"
            "  \"curtime\" : ttt,                  (numeric) current timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"bits\" : \"xxx\",                 (string) compressed target of next block\n"
            "  \"height\" : n                      (numeric) The height of the next block\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getblocktemplate", "")
            + HelpExampleRpc("getblocktemplate", "")
         );

    LOCK(cs_main); // ����

    std::string strMode = "template"; // ģʽ��Ĭ��Ϊ "template"
    UniValue lpval = NullUniValue;
    if (params.size() > 0) // ָ���˲���
    {
        const UniValue& oparam = params[0].get_obj(); // ��ȡ��������
        const UniValue& modeval = find_value(oparam, "mode"); // ��ȡ "mode" �ؼ��ֶ�Ӧ��ֵ
        if (modeval.isStr()) // �ַ�������
            strMode = modeval.get_str(); // ��ȡָ��ģʽ
        else if (modeval.isNull()) // ��
        {
            /* Do nothing */
        }
        else // ��������
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = find_value(oparam, "longpollid");

        if (strMode == "proposal") // "proposal" ģʽ
        {
            const UniValue& dataval = find_value(oparam, "data"); // ��ȡ����
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str())) // ���� 16 ���Ƶ�����
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash(); // ��ȡ�����ϣ
            BlockMap::iterator mi = mapBlockIndex.find(hash); // �����������б��в���ָ������
            if (mi != mapBlockIndex.end()) { // ���ҵ�
                CBlockIndex *pindex = mi->second; // ��ȡָ����������ָ��
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) // ��֤����
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK) // ����״̬
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            } // ��δ�ҵ�

            CBlockIndex* const pindexPrev = chainActive.Tip(); // ��ȡ��������
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash()) // ָ�������ǰһ�������ϣ�Ƿ�Ϊ��ǰ��������
                return "inconclusive-not-best-prevblk";
            CValidationState state;
            TestBlockValidity(state, Params(), block, pindexPrev, false, true); // ����������Ч��
            return BIP22ValidationResult(state); // ������֤���
        }
    }

    if (strMode != "template") // "template" ģʽ
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if (vNodes.empty()) // �ѽ������ӵĽڵ��б�ǿ�
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Bitcoin is not connected!");

    if (IsInitialBlockDownload()) // ����Ƿ��ʼ�����������
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Bitcoin is downloading blocks...");

    static unsigned int nTransactionsUpdatedLast;

    if (!lpval.isNull())
    { // �ȴ���Ӧ��ֱ����ѿ�ı䣬�� 1 ���ӹ�ȥ�и���Ľ���
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        boost::system_time checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            std::string lpstr = lpval.get_str();

            hashWatchedChain.SetHex(lpstr.substr(0, 64));
            nTransactionsUpdatedLastLP = atoi64(lpstr.substr(64));
        }
        else
        { // ע���淶û�жԷ��ַ����� longpollip ָ����Ϊ������ʹ���Ը�������
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = chainActive.Tip()->GetBlockHash(); // ��ȡ���������ϣ
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast; // ���µĽ��׸�������
        }

        // Release the wallet and main lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main); // �ڵȴ�ʱ�ͷ�Ǯ��������
        {
            checktxtime = boost::get_system_time() + boost::posix_time::minutes(1); // ��齻��ʱ��Ϊ 1 ���Ӻ�

            boost::unique_lock<boost::mutex> lock(csBestBlock); // �����������
            while (chainActive.Tip()->GetBlockHash() == hashWatchedChain && IsRPCRunning())
            { // �������δ�ı� �� RPC ������
                if (!cvBlockChange.timed_wait(lock, checktxtime)) // ��ʱ����齻�����ڸ���
                {
                    // Timeout: Check transactions for update
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += boost::posix_time::seconds(10); // ���ʱ��� 10 ��
                }
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        if (!IsRPCRunning()) // ��� RPC �����Ƿ���
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    // Update block // ��������
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static CBlockTemplate* pblocktemplate;
    if (pindexPrev != chainActive.Tip() || // �������ǿ� ��
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5)) // �����ڴ�ؽ��׸�������������������׸����� �� ��ǰʱ���ȥ 5 ��
    { // ��� pindexPrev �Ա㽫�����ô���һ���¿飬����������ܻ�ʧ��
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL; // �ÿ�

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated(); // ��ȡ��ǰ���׸�����
        CBlockIndex* pindexPrevNew = chainActive.Tip(); // ��ȡ��������
        nStart = GetTime();

        // Create new block
        if(pblocktemplate) // ������ģ���Ѵ���
        {
            delete pblocktemplate; // ��ɾ��
            pblocktemplate = NULL; // ���ÿ�
        }
        CScript scriptDummy = CScript() << OP_TRUE; // �ű�
        pblocktemplate = CreateNewBlock(Params(), scriptDummy); // ����һ���¿�
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew; // ������ֱ�������¿�ɹ�����Ҫ����ǰһ������Ĺ�ϣ
    }
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience

    // Update nTime
    UpdateTime(pblock, Params().GetConsensus(), pindexPrev); // ����ʱ��
    pblock->nNonce = 0; // ��ʼ�������

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    map<uint256, int64_t> setTxIndex; // ��������ӳ���б�
    int i = 0;
    BOOST_FOREACH (const CTransaction& tx, pblock->vtx) { // �������齻�������б�
        uint256 txHash = tx.GetHash(); // ��ȡ���׹�ϣ
        setTxIndex[txHash] = i++; // ���뽻������ӳ���б�

        if (tx.IsCoinBase()) // ��Ϊ���ҽ���
            continue; // ����

        UniValue entry(UniValue::VOBJ);

        entry.push_back(Pair("data", EncodeHexTx(tx))); // ���� 16 ���ƵĽ���

        entry.push_back(Pair("hash", txHash.GetHex())); // ��ȡ 16 ���ƵĽ�������

        UniValue deps(UniValue::VARR);
        BOOST_FOREACH (const CTxIn &in, tx.vin) // �������������б�
        {
            if (setTxIndex.count(in.prevout.hash)) // ��ǰһ�ʽ�������ڽ�������ӳ���б���
                deps.push_back(setTxIndex[in.prevout.hash]); // �������� json ����
        }
        entry.push_back(Pair("depends", deps)); // ��������

        int index_in_template = i - 1; // ��ǰ���׵��������
        entry.push_back(Pair("fee", pblocktemplate->vTxFees[index_in_template])); // ���׷�
        entry.push_back(Pair("sigops", pblocktemplate->vTxSigOps[index_in_template])); // ����ǩ������

        transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits); // �����Ѷ�Ŀ��ֵ

    static UniValue aMutable(UniValue::VARR);
    if (aMutable.empty())
    {
        aMutable.push_back("time"); // ʱ��
        aMutable.push_back("transactions"); // ����
        aMutable.push_back("prevblock"); // ǰһ������
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("capabilities", aCaps)); // ����
    result.push_back(Pair("version", pblock->nVersion)); // ����汾
    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex())); // ǰһ�������ϣ
    result.push_back(Pair("transactions", transactions)); // ����
    result.push_back(Pair("coinbaseaux", aux)); // coinbase aux
    result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue)); // ���ҽ���������
    result.push_back(Pair("longpollid", chainActive.Tip()->GetBlockHash().GetHex() + i64tostr(nTransactionsUpdatedLast)));
    result.push_back(Pair("target", hashTarget.GetHex())); // �Ѷ�Ŀ��
    result.push_back(Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff")); // �������Χ
    result.push_back(Pair("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS)); // ����ǩ��������������
    result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_SIZE)); // �����С����
    result.push_back(Pair("curtime", pblock->GetBlockTime())); // ���鴴��ʱ��
    result.push_back(Pair("bits", strprintf("%08x", pblock->nBits))); // �Ѷ�
    result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1))); // �߶�

    return result; // ���ؽ��
}

class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {};

protected:
    virtual void BlockChecked(const CBlock& block, const CValidationState& stateIn) {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    };
};

UniValue submitblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) // ����ֻ�� 1 ��
        throw runtime_error( // �����������
            "submitblock \"hexdata\" ( \"jsonparametersobject\" )\n"
            "\nAttempts to submit new block to network.\n"
            "The 'jsonparametersobject' parameter is currently ignored.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments\n"
            "1. \"hexdata\"    (string, required) the hex-encoded block data to submit\n"
            "2. \"jsonparametersobject\"     (string, optional) object of optional parameters\n"
            "    {\n"
            "      \"workid\" : \"id\"    (string, optional) if the server provided a workid, it MUST be included with submissions\n"
            "    }\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
        );

    CBlock block;
    if (!DecodeHexBlk(block, params[0].get_str())) // ���� 16 ���Ƶ���������
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    uint256 hash = block.GetHash(); // ��ȡ�����ϣ
    bool fBlockPresent = false;
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hash); // ͨ�����������õ��������Ӧ������
        if (mi != mapBlockIndex.end()) { // ����ҵ���
            CBlockIndex *pindex = mi->second; // ��ȡ����������
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                return "duplicate";
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return "duplicate-invalid";
            // Otherwise, we might only have the header - process the block before returning
            fBlockPresent = true;
        }
    }

    CValidationState state;
    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    bool fAccepted = ProcessNewBlock(state, Params(), NULL, &block, true, NULL);
    UnregisterValidationInterface(&sc);
    if (fBlockPresent)
    {
        if (fAccepted && !sc.found)
            return "duplicate-inconclusive";
        return "duplicate";
    }
    if (fAccepted)
    {
        if (!sc.found)
            return "inconclusive";
        state = sc.state;
    }
    return BIP22ValidationResult(state);
}

UniValue estimatefee(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
            "estimatefee nblocks\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within nblocks blocks.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric)\n"
            "\nResult:\n"
            "n              (numeric) estimated fee-per-kilobyte\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatefee", "6")
            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)); // �������ͼ��

    int nBlocks = params[0].get_int(); // ��ȡָ���Ŀ���
    if (nBlocks < 1) // �������Ϊ 1
        nBlocks = 1;

    CFeeRate feeRate = mempool.estimateFee(nBlocks); // �����ڴ��Ԥ�����׷ѣ�������������
    if (feeRate == CFeeRate(0)) // �����׷�Ϊ 0
        return -1.0; // ���� -1.0

    return ValueFromAmount(feeRate.GetFeePerK()); // ���򣬸�ʽ���󷵻�Ԥ�����׷�
}

UniValue estimatepriority(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
            "estimatepriority nblocks\n"
            "\nEstimates the approximate priority a zero-fee transaction needs to begin\n"
            "confirmation within nblocks blocks.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric)\n"
            "\nResult:\n"
            "n              (numeric) estimated priority\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatepriority", "6")
            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)); // ����������

    int nBlocks = params[0].get_int(); // ��ȡָ��������
    if (nBlocks < 1) // ��������Ϊ 1 ��
        nBlocks = 1;

    return mempool.estimatePriority(nBlocks); // �ڽ����ڴ���и��ݿ������㽻�����ȼ���������
}

UniValue estimatesmartfee(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
            "estimatesmartfee nblocks\n"
            "\nWARNING: This interface is unstable and may disappear or change!\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within nblocks blocks if possible and return the number of blocks\n"
            "for which the estimate is valid.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric)\n"
            "\nResult:\n"
            "{\n"
            "  \"feerate\" : x.x,     (numeric) estimate fee-per-kilobyte (in BTC)\n"
            "  \"blocks\" : n         (numeric) block number where estimate was found\n"
            "}\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
            "However it will not return a value below the mempool reject fee.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatesmartfee", "6")
            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)); // �������ͼ��

    int nBlocks = params[0].get_int(); // ��ȡָ����������

    UniValue result(UniValue::VOBJ);
    int answerFound; // ���������Ч�Ŀ���
    CFeeRate feeRate = mempool.estimateSmartFee(nBlocks, &answerFound); // ���ܹ��㽻�׷�
    result.push_back(Pair("feerate", feeRate == CFeeRate(0) ? -1.0 : ValueFromAmount(feeRate.GetFeePerK()))); // ���׷�
    result.push_back(Pair("blocks", answerFound)); // ��Ч��������
    return result; // ���ؽ��
}

UniValue estimatesmartpriority(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
            "estimatesmartpriority nblocks\n"
            "\nWARNING: This interface is unstable and may disappear or change!\n"
            "\nEstimates the approximate priority a zero-fee transaction needs to begin\n"
            "confirmation within nblocks blocks if possible and return the number of blocks\n"
            "for which the estimate is valid.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric)\n"
            "\nResult:\n"
            "{\n"
            "  \"priority\" : x.x,    (numeric) estimated priority\n"
            "  \"blocks\" : n         (numeric) block number where estimate was found\n"
            "}\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
            "However if the mempool reject fee is set it will return 1e9 * MAX_MONEY.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatesmartpriority", "6")
            );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)); // ����������

    int nBlocks = params[0].get_int(); // ��ȡָ����������

    UniValue result(UniValue::VOBJ);
    int answerFound; // ������Ч��������
    double priority = mempool.estimateSmartPriority(nBlocks, &answerFound); // ���ܹ���������ȼ�����ȡ������Ч��������
    result.push_back(Pair("priority", priority)); // �������ȼ�
    result.push_back(Pair("blocks", answerFound)); // ��Ч������
    return result; // ���ؽ����
}
