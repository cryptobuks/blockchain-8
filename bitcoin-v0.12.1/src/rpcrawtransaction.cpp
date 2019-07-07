// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "chain.h"
#include "coins.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "keystore.h"
#include "main.h"
#include "merkleblock.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "rpcserver.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"
#include "txmempool.h"
#include "uint256.h"
#include "utilstrencodings.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <stdint.h>

#include <boost/assign/list_of.hpp>

#include <univalue.h>

using namespace std;

void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.push_back(Pair("asm", ScriptToAsmStr(scriptPubKey))); // �ű�������
    if (fIncludeHex)
        out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end()))); // 16 ������ʽ

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.push_back(Pair("type", GetTxnOutputType(type))); // �ű�����
        return;
    }

    out.push_back(Pair("reqSigs", nRequired)); // �Ƿ���Ҫǩ��
    out.push_back(Pair("type", GetTxnOutputType(type))); // ����

    UniValue a(UniValue::VARR);
    BOOST_FOREACH(const CTxDestination& addr, addresses)
        a.push_back(CBitcoinAddress(addr).ToString());
    out.push_back(Pair("addresses", a)); // �����ַ
}

void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry)
{
    entry.push_back(Pair("txid", tx.GetHash().GetHex()));
    entry.push_back(Pair("size", (int)::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION)));
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("locktime", (int64_t)tx.nLockTime));
    UniValue vin(UniValue::VARR);
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase())
            in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
        else {
            in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
            in.push_back(Pair("vout", (int64_t)txin.prevout.n));
            UniValue o(UniValue::VOBJ);
            o.push_back(Pair("asm", ScriptToAsmStr(txin.scriptSig, true)));
            o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
            in.push_back(Pair("scriptSig", o));
        }
        in.push_back(Pair("sequence", (int64_t)txin.nSequence));
        vin.push_back(in);
    }
    entry.push_back(Pair("vin", vin));
    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];
        UniValue out(UniValue::VOBJ);
        out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
        out.push_back(Pair("n", (int64_t)i));
        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToJSON(txout.scriptPubKey, o, true);
        out.push_back(Pair("scriptPubKey", o));
        vout.push_back(out);
    }
    entry.push_back(Pair("vout", vout));

    if (!hashBlock.IsNull()) {
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex* pindex = (*mi).second;
            if (chainActive.Contains(pindex)) {
                entry.push_back(Pair("confirmations", 1 + chainActive.Height() - pindex->nHeight));
                entry.push_back(Pair("time", pindex->GetBlockTime()));
                entry.push_back(Pair("blocktime", pindex->GetBlockTime()));
            }
            else
                entry.push_back(Pair("confirmations", 0));
        }
    }
}

UniValue getrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) // ����Ϊ 1 �� 2 ��
        throw runtime_error( // �����������
            "getrawtransaction \"txid\" ( verbose )\n"
            "\nNOTE: By default this function only works sometimes. This is when the tx is in the mempool\n"
            "or there is an unspent output in the utxo for this transaction. To make it always work,\n"
            "you need to maintain a transaction index, using the -txindex command line option.\n"
            "\nReturn the raw transaction data.\n"
            "\nIf verbose=0, returns a string that is serialized, hex-encoded data for 'txid'.\n"
            "If verbose is non-zero, returns an Object with information about 'txid'.\n"

            "\nArguments:\n"
            "1. \"txid\"      (string, required) The transaction id\n"
            "2. verbose       (numeric, optional, default=0) If 0, return a string, other return a json object\n"

            "\nResult (if verbose is not set or set to 0):\n"
            "\"data\"      (string) The serialized, hex-encoded data for 'txid'\n"

            "\nResult (if verbose > 0):\n"
            "{\n"
            "  \"hex\" : \"data\",       (string) The serialized, hex-encoded data for 'txid'\n"
            "  \"txid\" : \"id\",        (string) The transaction id (same as provided)\n"
            "  \"size\" : n,             (numeric) The transaction size\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) \n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"sequence\": n      (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [              (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in " + CURRENCY_UNIT + "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"bitcoinaddress\"        (string) bitcoin address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"blockhash\" : \"hash\",   (string) the block hash\n"
            "  \"confirmations\" : n,      (numeric) The confirmations\n"
            "  \"time\" : ttt,             (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"blocktime\" : ttt         (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getrawtransaction", "\"mytxid\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1")
            + HelpExampleRpc("getrawtransaction", "\"mytxid\", 1")
        );

    LOCK(cs_main); // ����

    uint256 hash = ParseHashV(params[0], "parameter 1"); // ����ָ���Ľ��׹�ϣ

    bool fVerbose = false; // ��ϸ��Ϣ��־��Ĭ��Ϊ false
    if (params.size() > 1)
        fVerbose = (params[1].get_int() != 0); // ��ȡ��ϸ��Ϣ����

    CTransaction tx;
    uint256 hashBlock;
    if (!GetTransaction(hash, tx, Params().GetConsensus(), hashBlock, true)) // ��ȡ���׼����������ϣ
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

    string strHex = EncodeHexTx(tx); // ���뽻��

    if (!fVerbose) // ��Ϊ false
        return strHex; // ֱ�ӷ��ر���������

    UniValue result(UniValue::VOBJ); // ���򣬹����������ͷ��ؽ��
    result.push_back(Pair("hex", strHex)); // �������л��Ľ���
    TxToJSON(tx, hashBlock, result); // ������Ϣת��Ϊ JSON ��ʽ������
    return result; // ���ؽ��
}

UniValue gettxoutproof(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 1 && params.size() != 2)) // ����Ϊ 1 ���� 2 ��
        throw runtime_error( // �����������
            "gettxoutproof [\"txid\",...] ( blockhash )\n"
            "\nReturns a hex-encoded proof that \"txid\" was included in a block.\n"
            "\nNOTE: By default this function only works sometimes. This is when there is an\n"
            "unspent output in the utxo for this transaction. To make it always work,\n"
            "you need to maintain a transaction index, using the -txindex command line option or\n"
            "specify the block in which the transaction is included in manually (by blockhash).\n"
            "\nReturn the raw transaction data.\n"
            "\nArguments:\n"
            "1. \"txids\"       (string) A json array of txids to filter\n"
            "    [\n"
            "      \"txid\"     (string) A transaction hash\n"
            "      ,...\n"
            "    ]\n"
            "2. \"block hash\"  (string, optional) If specified, looks for txid in the block with this hash\n"
            "\nResult:\n"
            "\"data\"           (string) A string that is a serialized, hex-encoded data for the proof.\n"
        );

    set<uint256> setTxids; // ������������
    uint256 oneTxid;
    UniValue txids = params[0].get_array(); // ��ȡָ���Ľ���������
    for (unsigned int idx = 0; idx < txids.size(); idx++) { // �����ü���
        const UniValue& txid = txids[idx]; // ��ȡ��������
        if (txid.get_str().length() != 64 || !IsHex(txid.get_str())) // ���ȼ� 16 ������֤
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid txid ")+txid.get_str());
        uint256 hash(uint256S(txid.get_str()));
        if (setTxids.count(hash)) // ��ֻ֤����һ��
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated txid: ")+txid.get_str());
       setTxids.insert(hash); // ���뽻��������
       oneTxid = hash; // ��¼���һ�ʽ��׹�ϣ
    }

    LOCK(cs_main); // ����

    CBlockIndex* pblockindex = NULL;

    uint256 hashBlock;
    if (params.size() > 1) // ָ���������ϣ
    {
        hashBlock = uint256S(params[1].get_str()); // ��ȡָ�������ϣ
        if (!mapBlockIndex.count(hashBlock)) // ����������ӳ����û�и�����
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found"); // ����
        pblockindex = mapBlockIndex[hashBlock]; // ��ȡ��������
    } else { // δָ������
        CCoins coins;
        if (pcoinsTip->GetCoins(oneTxid, coins) && coins.nHeight > 0 && coins.nHeight <= chainActive.Height())
            pblockindex = chainActive[coins.nHeight]; // ��ȡ�ý������ڵ���������
    }

    if (pblockindex == NULL) // ����������������
    {
        CTransaction tx;
        if (!GetTransaction(oneTxid, tx, Params().GetConsensus(), hashBlock, false) || hashBlock.IsNull())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not yet in block");
        if (!mapBlockIndex.count(hashBlock)) // ��������������������ӳ���б���
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction index corrupt");
        pblockindex = mapBlockIndex[hashBlock]; // ��ȡ��������
    }

    CBlock block;
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) // ͨ�����������Ӵ��̶��������ݵ� block
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    unsigned int ntxFound = 0; // �ҵ����׵ĸ���
    BOOST_FOREACH(const CTransaction&tx, block.vtx) // �������齻���б�
        if (setTxids.count(tx.GetHash())) // ���ý�����ָ���Ľ��׼���
            ntxFound++; // +1
    if (ntxFound != setTxids.size()) // �ҵ����׸���������ڽ��׼���С����ָ�����ױ���ȫ���ҵ�
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "(Not all) transactions not found in specified block");

    CDataStream ssMB(SER_NETWORK, PROTOCOL_VERSION); // ��������������
    CMerkleBlock mb(block, setTxids); // �ѽ����������Լ���Ӧ��������ݹ���һ�� CMerkleBlock ����
    ssMB << mb; // ����������
    std::string strHex = HexStr(ssMB.begin(), ssMB.end()); // ת��Ϊ 16 ����
    return strHex; // ���ؽ��
}

UniValue verifytxoutproof(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
            "verifytxoutproof \"proof\"\n"
            "\nVerifies that a proof points to a transaction in a block, returning the transaction it commits to\n"
            "and throwing an RPC error if the block is not in our best chain\n"
            "\nArguments:\n"
            "1. \"proof\"    (string, required) The hex-encoded proof generated by gettxoutproof\n"
            "\nResult:\n"
            "[\"txid\"]      (array, strings) The txid(s) which the proof commits to, or empty array if the proof is invalid\n"
        );

    CDataStream ssMB(ParseHexV(params[0], "proof"), SER_NETWORK, PROTOCOL_VERSION); // ��ȡָ������֤����ʼ������������
    CMerkleBlock merkleBlock;
    ssMB >> merkleBlock; // ������ CMerkleBlock ������

    UniValue res(UniValue::VARR); // �������͵ķ��ض���

    vector<uint256> vMatch; // ���ڱ��潻������
    if (merkleBlock.txn.ExtractMatches(vMatch) != merkleBlock.header.hashMerkleRoot) // ��ȡ���������б�
        return res;

    LOCK(cs_main); // ����

    if (!mapBlockIndex.count(merkleBlock.header.GetHash()) || !chainActive.Contains(mapBlockIndex[merkleBlock.header.GetHash()])) // ��������ӳ���б��а��������飨ͷ������ �� �����������������
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");

    BOOST_FOREACH(const uint256& hash, vMatch) // �������������б�
        res.push_back(hash.GetHex()); // ��������
    return res; // ���ؽ��
}

UniValue createrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3) // 1.����Ϊ 2 �� 3 ��
        throw runtime_error( // �����������
            "createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] {\"address\":amount,\"data\":\"hex\",...} ( locktime )\n"
            "\nCreate a transaction spending the given inputs and creating new outputs.\n"
            "Outputs can be addresses or data.\n"
            "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not stored in the wallet or transmitted to the network.\n"

            "\nArguments:\n"
            "1. \"transactions\"        (string, required) A json array of json objects\n"
            "     [\n"
            "       {\n"
            "         \"txid\":\"id\",    (string, required) The transaction id\n"
            "         \"vout\":n        (numeric, required) The output number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"
            "2. \"outputs\"             (string, required) a json object with outputs\n"
            "    {\n"
            "      \"address\": x.xxx   (numeric or string, required) The key is the bitcoin address, the numeric value (can be string) is the " + CURRENCY_UNIT + " amount\n"
            "      \"data\": \"hex\",     (string, required) The key is \"data\", the value is hex encoded data\n"
            "      ...\n"
            "    }\n"
            "3. locktime                (numeric, optional, default=0) Raw locktime. Non-0 value also locktime-activates inputs\n"
            "\nResult:\n"
            "\"transaction\"            (string) hex string of the transaction\n"

            "\nExamples\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"address\\\":0.01}\"")
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"data\\\":\\\"00010203\\\"}\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"address\\\":0.01}\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"data\\\":\\\"00010203\\\"}\"")
        );

    LOCK(cs_main); // 2.����
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VARR)(UniValue::VOBJ)(UniValue::VNUM), true); // 3.����������
    if (params[0].isNull() || params[1].isNull()) // ��������������Ϊ��
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 must be non-null");

    UniValue inputs = params[0].get_array(); // ��ȡ����
    UniValue sendTo = params[1].get_obj(); // ��ȡ���

    CMutableTransaction rawTx; // 4.����һ��ԭʼ����

    if (params.size() > 2 && !params[2].isNull()) { // 4.1.��ָ��������ʱ��
        int64_t nLockTime = params[2].get_int64(); // ��ȡ����ʱ��
        if (nLockTime < 0 || nLockTime > std::numeric_limits<uint32_t>::max()) // ����ʱ�䷶Χ���
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        rawTx.nLockTime = nLockTime; // ��������ʱ���ʼ��
    }

    for (unsigned int idx = 0; idx < inputs.size(); idx++) { // 4.2.�������룬����ԭʼ���������б�
        const UniValue& input = inputs[idx]; // ��ȡһ������
        const UniValue& o = input.get_obj(); // �õ����������

        uint256 txid = ParseHashO(o, "txid"); // ��ȡ��������

        const UniValue& vout_v = find_value(o, "vout"); // ��ȡ������
        if (!vout_v.isNum()) // �����ű���Ϊ����
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int(); // ��ȡ������
        if (nOutput < 0) // ���������СΪ 0
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        uint32_t nSequence = (rawTx.nLockTime ? std::numeric_limits<uint32_t>::max() - 1 : std::numeric_limits<uint32_t>::max()); // ����ʱ��
        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence); // ����һ�������������

        rawTx.vin.push_back(in); // ����ԭʼ���������б�
    }

    set<CBitcoinAddress> setAddress; // ��ַ��
    vector<string> addrList = sendTo.getKeys(); // ��ȡ��������йؼ��֣���ַ��
    BOOST_FOREACH(const string& name_, addrList) { // 4.3.������ַ�б�

        if (name_ == "data") { // ���ؼ����а��� "data"
            std::vector<unsigned char> data = ParseHexV(sendTo[name_].getValStr(),"Data"); // ��������

            CTxOut out(0, CScript() << OP_RETURN << data); // ���������������
            rawTx.vout.push_back(out); // ����ԭʼ��������б�
        } else { // ����ΪĿ�ĵ�ַ
            CBitcoinAddress address(name_); // �������رҵ�ַ
            if (!address.IsValid()) // �����ַ�Ƿ���Ч
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Bitcoin address: ")+name_);

            if (setAddress.count(address)) // ��֤��ַ���в����ڸõ�ַ����ֹ��ַ�ظ�����
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
            setAddress.insert(address); // �����ַ��

            CScript scriptPubKey = GetScriptForDestination(address.Get()); // ��Ŀ�ĵ�ַ��ȡ�ű���Կ
            CAmount nAmount = AmountFromValue(sendTo[name_]); // ��ȡ���

            CTxOut out(nAmount, scriptPubKey); // ���������������
            rawTx.vout.push_back(out); // ����ԭʼ��������б�
        }
    }

    return EncodeHexTx(rawTx); // 5.16 ���Ʊ����ԭʼ���ײ�����
}

UniValue decoderawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // ��������Ϊ 1 ��
        throw runtime_error( // �����������
            "decoderawtransaction \"hexstring\"\n"
            "\nReturn a JSON object representing the serialized, hex-encoded transaction.\n"

            "\nArguments:\n"
            "1. \"hex\"      (string, required) The transaction hex string\n"

            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"id\",        (string) The transaction id\n"
            "  \"size\" : n,             (numeric) The transaction size\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) The output number\n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"sequence\": n     (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [             (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in " + CURRENCY_UNIT + "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"12tvKAXCxZjSmdNbao16dKXC8tRWfcF5oc\"   (string) bitcoin address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("decoderawtransaction", "\"hexstring\"")
            + HelpExampleRpc("decoderawtransaction", "\"hexstring\"")
        );

    LOCK(cs_main); // ����
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)); // ����������

    CTransaction tx;

    if (!DecodeHexTx(tx, params[0].get_str())) // ���뽻��
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    UniValue result(UniValue::VOBJ);
    TxToJSON(tx, uint256(), result); // �ѽ�����Ϣת��Ϊ JSON ����������

    return result; // ���ؽ������
}

UniValue decodescript(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) // ���������� 1 ��
        throw runtime_error( // �����������
            "decodescript \"hex\"\n"
            "\nDecode a hex-encoded script.\n"
            "\nArguments:\n"
            "1. \"hex\"     (string) the hex encoded script\n"
            "\nResult:\n"
            "{\n"
            "  \"asm\":\"asm\",   (string) Script public key\n"
            "  \"hex\":\"hex\",   (string) hex encoded public key\n"
            "  \"type\":\"type\", (string) The output type\n"
            "  \"reqSigs\": n,    (numeric) The required signatures\n"
            "  \"addresses\": [   (json array of string)\n"
            "     \"address\"     (string) bitcoin address\n"
            "     ,...\n"
            "  ],\n"
            "  \"p2sh\",\"address\" (string) script address\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("decodescript", "\"hexstring\"")
            + HelpExampleRpc("decodescript", "\"hexstring\"")
        );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)); // �������ͼ��

    UniValue r(UniValue::VOBJ);
    CScript script;
    if (params[0].get_str().size() > 0){ // ���ű��ǿ��ַ���
        vector<unsigned char> scriptData(ParseHexV(params[0], "argument")); // ��������
        script = CScript(scriptData.begin(), scriptData.end()); // �������л��Ľű�
    } else { // �սű�����Ч��
        // Empty scripts are valid
    }
    ScriptPubKeyToJSON(script, r, false); // �ű���Կת��Ϊ JSON ��ʽ��������

    r.push_back(Pair("p2sh", CBitcoinAddress(CScriptID(script)).ToString())); // Base58 ����Ľű���ϣ
    return r; // ���ؽ����
}

/** Pushes a JSON object for script verification or signing errors to vErrorsRet. */
static void TxInErrorToJSON(const CTxIn& txin, UniValue& vErrorsRet, const std::string& strMessage)
{
    UniValue entry(UniValue::VOBJ);
    entry.push_back(Pair("txid", txin.prevout.hash.ToString()));
    entry.push_back(Pair("vout", (uint64_t)txin.prevout.n));
    entry.push_back(Pair("scriptSig", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    entry.push_back(Pair("sequence", (uint64_t)txin.nSequence));
    entry.push_back(Pair("error", strMessage));
    vErrorsRet.push_back(entry);
}

UniValue signrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 4) // 1.�������� 1 �������� 4 ��
        throw runtime_error( // �����������
            "signrawtransaction \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )\n"
            "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
            "The second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
            "The third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"
#ifdef ENABLE_WALLET
            + HelpRequiringPassphrase() + "\n"
#endif

            "\nArguments:\n"
            "1. \"hexstring\"     (string, required) The transaction hex string\n"
            "2. \"prevtxs\"       (string, optional) An json array of previous dependent transaction outputs\n"
            "     [               (json array of json objects, or 'null' if none provided)\n"
            "       {\n"
            "         \"txid\":\"id\",             (string, required) The transaction id\n"
            "         \"vout\":n,                  (numeric, required) The output number\n"
            "         \"scriptPubKey\": \"hex\",   (string, required) script key\n"
            "         \"redeemScript\": \"hex\"    (string, required for P2SH) redeem script\n"
            "       }\n"
            "       ,...\n"
            "    ]\n"
            "3. \"privatekeys\"     (string, optional) A json array of base58-encoded private keys for signing\n"
            "    [                  (json array of strings, or 'null' if none provided)\n"
            "      \"privatekey\"   (string) private key in base58-encoding\n"
            "      ,...\n"
            "    ]\n"
            "4. \"sighashtype\"     (string, optional, default=ALL) The signature hash type. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"

            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"value\",           (string) The hex-encoded raw transaction with signature(s)\n"
            "  \"complete\" : true|false,   (boolean) If the transaction has a complete set of signatures\n"
            "  \"errors\" : [                 (json array of objects) Script verification errors (if there are any)\n"
            "    {\n"
            "      \"txid\" : \"hash\",           (string) The hash of the referenced, previous transaction\n"
            "      \"vout\" : n,                (numeric) The index of the output to spent and used as input\n"
            "      \"scriptSig\" : \"hex\",       (string) The hex-encoded signature script\n"
            "      \"sequence\" : n,            (numeric) Script sequence number\n"
            "      \"error\" : \"text\"           (string) Verification or signing error related to the input\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("signrawtransaction", "\"myhex\"")
            + HelpExampleRpc("signrawtransaction", "\"myhex\"")
        );

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL); // 2.Ǯ������
#else
    LOCK(cs_main);
#endif
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VARR)(UniValue::VARR)(UniValue::VSTR), true); // 3.����������

    vector<unsigned char> txData(ParseHexV(params[0], "argument 1")); // ������һ������
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION); // ��������������
    vector<CMutableTransaction> txVariants; // �ɱ�Ľ����б�
    while (!ssData.empty()) { // ������������ǿ�
        try {
            CMutableTransaction tx; // �ɱ�汾�Ľ���
            ssData >> tx; // ����һ�ʽ���
            txVariants.push_back(tx); // ���뽻���б�
        }
        catch (const std::exception&) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
        }
    }

    if (txVariants.empty()) // �б�ǿգ�������һ�ʽ���
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transaction");

    // mergedTx will end up with all the signatures; it // mergeTx ����ȫ��ǩ��Ϊ��β��
    // starts as a clone of the rawtx: // ����Ϊ rawtx �ĸ�����ʼ��
    CMutableTransaction mergedTx(txVariants[0]); // �ϲ��Ŀɱ佻�����뼯

    // Fetch previous transactions (inputs): // ��ȡ֮ǰ�Ľ��ף����룩��
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    { // ��ʼ�����ڴ��
        LOCK(mempool.cs); // �����ڴ������
        CCoinsViewCache &viewChain = *pcoinsTip; // ��ȡ����� CCoinsView
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        BOOST_FOREACH(const CTxIn& txin, mergedTx.vin) { // �������������б�
            const uint256& prevHash = txin.prevout.hash; // ��ȡ���������ǰһ�ʽ��׹�ϣ
            CCoins coins;
            view.AccessCoins(prevHash); // this is certainly allowed to fail // ����϶���ʧ��
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long // �л����Ա��������ڴ��ʱ�����
    }

    bool fGivenKeys = false; // ָ����Կ��־��Ĭ��Ϊ false
    CBasicKeyStore tempKeystore; // ��ʱ˽Կ��
    if (params.size() > 2 && !params[2].isNull()) { // ��ָ������Կ
        fGivenKeys = true; // ��־��Ϊ true
        UniValue keys = params[2].get_array(); // ��ȡ��Կ����
        for (unsigned int idx = 0; idx < keys.size(); idx++) { // ����������
            UniValue k = keys[idx]; // ��ȡһ�� base58 �������Կ
            CBitcoinSecret vchSecret; // ���ر���Կ����
            bool fGood = vchSecret.SetString(k.get_str()); // ��ʼ����Կ
            if (!fGood)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            CKey key = vchSecret.GetKey(); // ��ȡ˽Կ
            if (!key.IsValid()) // ��֤˽Կ�Ƿ���Ч
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");
            tempKeystore.AddKey(key); // ��ӵ���ʱ˽Կ��
        }
    }
#ifdef ENABLE_WALLET
    else if (pwalletMain)
        EnsureWalletIsUnlocked(); // ȷ����ʱǮ�����ڽ���״̬
#endif

    // Add previous txouts given in the RPC call:
    if (params.size() > 1 && !params[1].isNull()) { // ��ָ����ǰһ�ʽ���������ϣ��ҷǿ�
        UniValue prevTxs = params[1].get_array(); // ��ȡǰһ�ʽ������������
        for (unsigned int idx = 0; idx < prevTxs.size(); idx++) { // ����������
            const UniValue& p = prevTxs[idx]; // ��ȡһ�������������
            if (!p.isObject()) // ȷ���Ƕ�������
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

            UniValue prevOut = p.get_obj(); // ��ȡ�������

            RPCTypeCheckObj(prevOut, boost::assign::map_list_of("txid", UniValue::VSTR)("vout", UniValue::VNUM)("scriptPubKey", UniValue::VSTR)); // �������ͼ��

            uint256 txid = ParseHashO(prevOut, "txid"); // ������������

            int nOut = find_value(prevOut, "vout").get_int(); // ��ȡ����������
            if (nOut < 0) // �����СΪ 0
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");

            vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey")); // �����ű���Կ
            CScript scriptPubKey(pkData.begin(), pkData.end()); // ����һ���ű���Կ����

            {
                CCoinsModifier coins = view.ModifyCoins(txid); // ��ȡ����������Ӧ�Ŀ��޸� CCoins
                if (coins->IsAvailable(nOut) && coins->vout[nOut].scriptPubKey != scriptPubKey) { // �������Ľű���Կ�Ƿ�һ��
                    string err("Previous output scriptPubKey mismatch:\n");
                    err = err + ScriptToAsmStr(coins->vout[nOut].scriptPubKey) + "\nvs:\n"+
                        ScriptToAsmStr(scriptPubKey);
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
                if ((unsigned int)nOut >= coins->vout.size()) // ���������������ڵ��ڱ������С
                    coins->vout.resize(nOut+1); // ������������б��С +1
                coins->vout[nOut].scriptPubKey = scriptPubKey; // ��������б��������Ӧ�Ľű���Կ
                coins->vout[nOut].nValue = 0; // we don't know the actual output value // �����Ӧ��ֵ��ʼ��Ϊ 0
            }

            // if redeemScript given and not using the local wallet (private keys // �����������ؽű����Ҳ�ʹ�ñ���Ǯ�����ṩ��˽Կ����
            // given), add redeemScript to the tempKeystore so it can be signed: // �����ؽű�����ʱ��Կ�������ڶ���ǩ����
            if (fGivenKeys && scriptPubKey.IsPayToScriptHash()) { // ����� P2SH
                RPCTypeCheckObj(prevOut, boost::assign::map_list_of("txid", UniValue::VSTR)("vout", UniValue::VNUM)("scriptPubKey", UniValue::VSTR)("redeemScript",UniValue::VSTR)); // �Ƚ��в������ͼ��
                UniValue v = find_value(prevOut, "redeemScript"); // ��ȡ��ؽű�
                if (!v.isNull()) { // �ű��ǿ�
                    vector<unsigned char> rsData(ParseHexV(v, "redeemScript"));
                    CScript redeemScript(rsData.begin(), rsData.end()); // �����ű�����
                    tempKeystore.AddCScript(redeemScript); // ��ӽű�����ʱ��Կ��
                }
            }
        }
    }

#ifdef ENABLE_WALLET
    const CKeyStore& keystore = ((fGivenKeys || !pwalletMain) ? tempKeystore : *pwalletMain); // ���ṩ����Կ �� ��Ǯ����Ч�����ȡ��ʱ��Կ�������
#else
    const CKeyStore& keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL; // �ű���ϣ���ͣ�Ĭ��Ϊ ALL
    if (params.size() > 3 && !params[3].isNull()) { // ��ָ��������
        static map<string, int> mapSigHashValues =
            boost::assign::map_list_of
            (string("ALL"), int(SIGHASH_ALL))
            (string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))
            (string("NONE"), int(SIGHASH_NONE))
            (string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY))
            (string("SINGLE"), int(SIGHASH_SINGLE))
            (string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
            ; // ǩ����ϣֵ����ӳ���б�
        string strHashType = params[3].get_str(); // ��ȡ��ϣ����
        if (mapSigHashValues.count(strHashType)) // ����ӳ���б��д���ָ���Ĺ�ϣ����
            nHashType = mapSigHashValues[strHashType]; // ���ýű���ϣ����
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
    }

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Script verification errors
    UniValue vErrors(UniValue::VARR); // �������͵Ľű���֤����

    // Sign what we can: // 4.����ǩ����
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) { // �����ϲ��Ŀɱ佻�������б�
        CTxIn& txin = mergedTx.vin[i]; // ��ȡһ�ʽ�������
        const CCoins* coins = view.AccessCoins(txin.prevout.hash); // ��ȡ������������ǰһ�ʽ��׵Ĺ�ϣ��Ӧ�� CCoins
        if (coins == NULL || !coins->IsAvailable(txin.prevout.n)) {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = coins->vout[txin.prevout.n].scriptPubKey; // ��ȡǰһ�ʽ�������Ľű���Կ

        txin.scriptSig.clear(); // ��ս�������Ľű�ǩ��
        // Only sign SIGHASH_SINGLE if there's a corresponding output: // �������Ӧ�������ֻǩ�� SIGHASH_SINGLE
        if (!fHashSingle || (i < mergedTx.vout.size()))
            SignSignature(keystore, prevPubKey, mergedTx, i, nHashType); // ǩ��

        // ... and merge in other signatures: // ... ���źϲ�����ǩ����
        BOOST_FOREACH(const CMutableTransaction& txv, txVariants) { // ���������б�
            txin.scriptSig = CombineSignatures(prevPubKey, mergedTx, i, txin.scriptSig, txv.vin[i].scriptSig); // �ϲ���������ǩ��
        }
        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker(&mergedTx, i), &serror)) { // ��֤�ű�ǩ��
            TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
        }
    }
    bool fComplete = vErrors.empty(); // ��û�д��󣬱�ʾ�����

    UniValue result(UniValue::VOBJ); // �����������͵Ľ����
    result.push_back(Pair("hex", EncodeHexTx(mergedTx))); // �ϲ��Ľ��׵� 16 ���Ʊ���
    result.push_back(Pair("complete", fComplete)); // �Ƿ����ǩ��
    if (!vErrors.empty()) {
        result.push_back(Pair("errors", vErrors)); // ������Ϣ
    }

    return result; // ���ؽ����
}

UniValue sendrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) // 1.����Ϊ 1 �� 2 ��
        throw runtime_error( // �����������
            "sendrawtransaction \"hexstring\" ( allowhighfees )\n"
            "\nSubmits raw transaction (serialized, hex-encoded) to local node and network.\n"
            "\nAlso see createrawtransaction and signrawtransaction calls.\n"
            "\nArguments:\n"
            "1. \"hexstring\"    (string, required) The hex string of the raw transaction)\n"
            "2. allowhighfees    (boolean, optional, default=false) Allow high fees\n"
            "\nResult:\n"
            "\"hex\"             (string) The transaction hash in hex\n"
            "\nExamples:\n"
            "\nCreate a transaction\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" \"{\\\"myaddress\\\":0.01}\"") +
            "Sign the transaction, and get back the hex\n"
            + HelpExampleCli("signrawtransaction", "\"myhex\"") +
            "\nSend the transaction (signed hex)\n"
            + HelpExampleCli("sendrawtransaction", "\"signedhex\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendrawtransaction", "\"signedhex\"")
        );

    LOCK(cs_main); // 2.����
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VBOOL)); // 3.�������ͼ��

    // parse hex string from parameter
    CTransaction tx; // ���׶���
    if (!DecodeHexTx(tx, params[0].get_str())) // �Ӳ������� 16 �����ַ���
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    uint256 hashTx = tx.GetHash(); // ��ȡ���׹�ϣ

    bool fOverrideFees = false; // ���׷ѳ����־��Ĭ�ϲ�����
    if (params.size() > 1)
        fOverrideFees = params[1].get_bool(); // ��ȡ���׷ѳ�������

    CCoinsViewCache &view = *pcoinsTip;
    const CCoins* existingCoins = view.AccessCoins(hashTx); // ��ȡ�ý��׵��޼��汾
    bool fHaveMempool = mempool.exists(hashTx); // �����ڴ�����Ƿ���ڸý���
    bool fHaveChain = existingCoins && existingCoins->nHeight < 1000000000; // ���׵ĸ߶�����
    if (!fHaveMempool && !fHaveChain) { // 4.���ý��ײ��ڽ����ڴ���� �� �����˸߶����Ƽ�û������
        // push to local node and sync with wallets // ���͵����ؽڵ㲢ͬ��Ǯ��
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, tx, false, &fMissingInputs, false, !fOverrideFees)) { // ���뽻���ڴ��
            if (state.IsInvalid()) { // ����״̬���
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            } else {
                if (fMissingInputs) {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
            }
        }
    } else if (fHaveChain) {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    }
    RelayTransaction(tx); // 5.Ȼ���м̣����ͣ��ý���

    return hashTx.GetHex(); // 6.���׹�ϣת��Ϊ 16 ���Ʋ�����
}
