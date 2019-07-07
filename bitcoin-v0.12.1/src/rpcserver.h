// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPCSERVER_H
#define BITCOIN_RPCSERVER_H

#include "amount.h"
#include "rpcprotocol.h"
#include "uint256.h"

#include <list>
#include <map>
#include <stdint.h>
#include <string>

#include <boost/function.hpp>

#include <univalue.h>

class CRPCCommand;

namespace RPCServer // RPC ����
{
    void OnStarted(boost::function<void ()> slot);
    void OnStopped(boost::function<void ()> slot);
    void OnPreCommand(boost::function<void (const CRPCCommand&)> slot);
    void OnPostCommand(boost::function<void (const CRPCCommand&)> slot);
}

class CBlockIndex;
class CNetAddr;

class JSONRequest // JSON ������
{
public:
    UniValue id; // ����� id
    std::string strMethod; // ����ķ���
    UniValue params;

    JSONRequest() { id = NullUniValue; }
    void parse(const UniValue& valRequest); // ���� JSON ����
};

/** Query whether RPC is running */
bool IsRPCRunning(); // ��ѯ RPC �����Ƿ�����

/**
 * Set the RPC warmup status.  When this is done, all RPC calls will error out
 * immediately with RPC_IN_WARMUP.
 */ // ���� RPC Ԥ����״̬�����ⲽ���ʱ��ȫ�� RPC ���ý�����ʹ�� RPC_IN_WARMUP ���������
void SetRPCWarmupStatus(const std::string& newStatus);
/* Mark warmup as done.  RPC calls will be processed from now on.  */
void SetRPCWarmupFinished(); // ���Ԥ����ɣ������ڿ�ʼ���� RPC ����

/* returns the current warmup state.  */
bool RPCIsInWarmup(std::string *statusOut); // ��ȡ��ǰ RPC ��Ԥ��״̬

/**
 * Type-check arguments; throws JSONRPCError if wrong type given. Does not check that
 * the right number of arguments are passed, just that any passed are the correct type.
 * Use like:  RPCTypeCheck(params, boost::assign::list_of(str_type)(int_type)(obj_type));
 */ // ���������ͣ���������������ͣ����׳� JSONRPCError������鴫�ݲ����ĸ����������������͡�
void RPCTypeCheck(const UniValue& params,
                  const std::list<UniValue::VType>& typesExpected, bool fAllowNull=false);

/*
  Check for expected keys/value types in an Object.
  Use like: RPCTypeCheckObj(object, boost::assign::map_list_of("name", str_type)("value", int_type));
*/
void RPCTypeCheckObj(const UniValue& o,
                  const std::map<std::string, UniValue::VType>& typesExpected, bool fAllowNull=false);

/** Opaque base class for timers returned by NewTimerFunc.
 * This provides no methods at the moment, but makes sure that delete
 * cleans up the whole state.
 */
class RPCTimerBase
{
public:
    virtual ~RPCTimerBase() {}
};

/**
 * RPC timer "driver".
 */ // RPC ��ʱ������������
class RPCTimerInterface // RPC ��ʱ���ӿ���
{
public:
    virtual ~RPCTimerInterface() {}
    /** Implementation name */
    virtual const char *Name() = 0;
    /** Factory function for timers.
     * RPC will call the function to create a timer that will call func in *millis* milliseconds.
     * @note As the RPC mechanism is backend-neutral, it can use different implementations of timers.
     * This is needed to cope with the case in which there is no HTTP server, but
     * only GUI RPC console, and to break the dependency of pcserver on httprpc.
     */
    virtual RPCTimerBase* NewTimer(boost::function<void(void)>& func, int64_t millis) = 0;
};

/** Register factory function for timers */ // ע�ᶨʱ����������
void RPCRegisterTimerInterface(RPCTimerInterface *iface);
/** Unregister factory function for timers */ // ��ע�ᶨʱ����������
void RPCUnregisterTimerInterface(RPCTimerInterface *iface);

/**
 * Run func nSeconds from now.
 * Overrides previous timer <name> (if any).
 */ // �����ڿ�ʼ�� nSeconds ������иú���
void RPCRunLater(const std::string& name, boost::function<void(void)> func, int64_t nSeconds);

typedef UniValue(*rpcfn_type)(const UniValue& params, bool fHelp); // RPC �����Ӧ������Ϊ�Ļص�����

class CRPCCommand // RPC ������
{
public:
    std::string category; // �������
    std::string name; // ����
    rpcfn_type actor; // ��Ӧ�ĺ�����Ϊ
    bool okSafeMode; // �Ƿ�����ȫģʽ
};

/**
 * Bitcoin RPC command dispatcher.
 */ // ���ر� RPC ���������
class CRPCTable // RPC �б���
{
private:
    std::map<std::string, const CRPCCommand*> mapCommands; // RPC �����б�
public:
    CRPCTable(); // ע�����ж���� RPC ��� RPC �����б�
    const CRPCCommand* operator[](const std::string& name) const; // ���ص��±������
    std::string help(const std::string& name) const;

    /**
     * Execute a method.
     * @param method   Method to execute
     * @param params   UniValue Array of arguments (JSON objects)
     * @returns Result of the call.
     * @throws an exception (UniValue) when an error happens.
     */ // ִ��һ������
    UniValue execute(const std::string &method, const UniValue &params) const;
};

extern const CRPCTable tableRPC; // �� rpcserver.cpp �д�����һ��ȫ�ֵĳ�������

/**
 * Utilities: convert hex-encoded Values
 * (throws error if not hex).
 */
extern uint256 ParseHashV(const UniValue& v, std::string strName);
extern uint256 ParseHashO(const UniValue& o, std::string strKey);
extern std::vector<unsigned char> ParseHexV(const UniValue& v, std::string strName);
extern std::vector<unsigned char> ParseHexO(const UniValue& o, std::string strKey);

extern int64_t nWalletUnlockTime;
extern CAmount AmountFromValue(const UniValue& value); // ��ָ��ֵ��ȡ���������ͺͷ�Χ���
extern UniValue ValueFromAmount(const CAmount& amount);
extern double GetDifficulty(const CBlockIndex* blockindex = NULL);
extern std::string HelpRequiringPassphrase();
extern std::string HelpExampleCli(const std::string& methodname, const std::string& args);
extern std::string HelpExampleRpc(const std::string& methodname, const std::string& args);

extern void EnsureWalletIsUnlocked();

extern UniValue getconnectioncount(const UniValue& params, bool fHelp); // ��ȡ��ǰ��������
extern UniValue getpeerinfo(const UniValue& params, bool fHelp); // ��ȡͬ���ڵ���Ϣ
extern UniValue ping(const UniValue& params, bool fHelp); // ping ������ getpeerinfo ����� pingtime �ֶβ鿴
extern UniValue addnode(const UniValue& params, bool fHelp); // ��ӽڵ�
extern UniValue disconnectnode(const UniValue& params, bool fHelp); // �Ͽ���ָ���ڵ������
extern UniValue getaddednodeinfo(const UniValue& params, bool fHelp); // ��ȡ��ӽڵ����Ϣ
extern UniValue getnettotals(const UniValue& params, bool fHelp); // ��ȡ����������Ϣ
extern UniValue setban(const UniValue& params, bool fHelp); // ���ú�����
extern UniValue listbanned(const UniValue& params, bool fHelp); // �г�������
extern UniValue clearbanned(const UniValue& params, bool fHelp); // ��պ�����

extern UniValue dumpprivkey(const UniValue& params, bool fHelp); // ����˽Կ
extern UniValue importprivkey(const UniValue& params, bool fHelp); // ����˽Կ
extern UniValue importaddress(const UniValue& params, bool fHelp); // �����ַ��ű�
extern UniValue importpubkey(const UniValue& params, bool fHelp); // ���빫Կ
extern UniValue dumpwallet(const UniValue& params, bool fHelp); // ����Ǯ��
extern UniValue importwallet(const UniValue& params, bool fHelp); // ����Ǯ��

extern UniValue getgenerate(const UniValue& params, bool fHelp); // ��ȡ�ڿ�״̬
extern UniValue setgenerate(const UniValue& params, bool fHelp); // �����ڿ�״̬���ڿ󿪹�
extern UniValue generate(const UniValue& params, bool fHelp); // ����ָ����Ŀ�����飨�ع�������ã�
extern UniValue getnetworkhashps(const UniValue& params, bool fHelp); // ��ȡȫ������
extern UniValue getmininginfo(const UniValue& params, bool fHelp); // ��ȡ�ڿ���Ϣ
extern UniValue prioritisetransaction(const UniValue& params, bool fHelp); // ���ý��׵����ȼ�
extern UniValue getblocktemplate(const UniValue& params, bool fHelp); // ��ȡ����ģ��
extern UniValue submitblock(const UniValue& params, bool fHelp); // �ύ����
extern UniValue estimatefee(const UniValue& params, bool fHelp); // Ԥ�����׷�
extern UniValue estimatepriority(const UniValue& params, bool fHelp); // Ԥ���������ȼ�
extern UniValue estimatesmartfee(const UniValue& params, bool fHelp); // ���ܹ��ƽ��׷�
extern UniValue estimatesmartpriority(const UniValue& params, bool fHelp); // ���ܹ��ƽ������ȼ�

extern UniValue getnewaddress(const UniValue& params, bool fHelp); // ��ȡ�µ�ַ
extern UniValue getaccountaddress(const UniValue& params, bool fHelp); // ��ȡ�˻��տ��ַ
extern UniValue getrawchangeaddress(const UniValue& params, bool fHelp); // ��ȡԪ���������ַ
extern UniValue setaccount(const UniValue& params, bool fHelp); // ���õ�ַ�����˻�
extern UniValue getaccount(const UniValue& params, bool fHelp); // ��ȡ��ַ�����˻�
extern UniValue getaddressesbyaccount(const UniValue& params, bool fHelp); // ��ȡ�˻��µ����е�ַ
extern UniValue sendtoaddress(const UniValue& params, bool fHelp); // ���ͱ��رҵ�ָ����ַ
extern UniValue signmessage(const UniValue& params, bool fHelp); // ǩ����Ϣ
extern UniValue verifymessage(const UniValue& params, bool fHelp); // ��֤ǩ����Ϣ
extern UniValue getreceivedbyaddress(const UniValue& params, bool fHelp); // ��ȡĳ��ַ���յ��Ľ��
extern UniValue getreceivedbyaccount(const UniValue& params, bool fHelp); // ��ȡĳ�˻����յ��Ľ��
extern UniValue getbalance(const UniValue& params, bool fHelp); // ��ȡ���
extern UniValue getunconfirmedbalance(const UniValue& params, bool fHelp); // ��ȡδȷ�ϵ����
extern UniValue movecmd(const UniValue& params, bool fHelp); // �˻���ת���ʽ�
extern UniValue sendfrom(const UniValue& params, bool fHelp); // ��ָ���˻����ͽ��
extern UniValue sendmany(const UniValue& params, bool fHelp); // ���ͽ������ַ
extern UniValue addmultisigaddress(const UniValue& params, bool fHelp); // ��Ӷ���ǩ����ַ
extern UniValue createmultisig(const UniValue& params, bool fHelp); // ��������ǩ��
extern UniValue listreceivedbyaddress(const UniValue& params, bool fHelp); // �г���ַ���
extern UniValue listreceivedbyaccount(const UniValue& params, bool fHelp); // �г��˻����
extern UniValue listtransactions(const UniValue& params, bool fHelp); // �г�����Ľ�����Ϣ
extern UniValue listaddressgroupings(const UniValue& params, bool fHelp); // �г���ַ����
extern UniValue listaccounts(const UniValue& params, bool fHelp); // �г��˻��������
extern UniValue listsinceblock(const UniValue& params, bool fHelp); // �г�ָ�����鿪ʼ�����ϵ�ȫ������
extern UniValue gettransaction(const UniValue& params, bool fHelp); // ��ȡ������ϸ��Ϣ
extern UniValue abandontransaction(const UniValue& params, bool fHelp); // ����Ǯ���ڵĽ���
extern UniValue backupwallet(const UniValue& params, bool fHelp); // ����Ǯ��
extern UniValue keypoolrefill(const UniValue& params, bool fHelp); // �������Կ��
extern UniValue walletpassphrase(const UniValue& params, bool fHelp); // Ǯ������
extern UniValue walletpassphrasechange(const UniValue& params, bool fHelp); // �޸�Ǯ������
extern UniValue walletlock(const UniValue& params, bool fHelp); // ����Ǯ��
extern UniValue encryptwallet(const UniValue& params, bool fHelp); // ����Ǯ��
extern UniValue validateaddress(const UniValue& params, bool fHelp); // ��֤��ַ
extern UniValue getinfo(const UniValue& params, bool fHelp); // ��ȡ���رҺ�����Ϣ
extern UniValue getwalletinfo(const UniValue& params, bool fHelp); // ��ȡǮ����Ϣ
extern UniValue getblockchaininfo(const UniValue& params, bool fHelp); // ��ȡ��������Ϣ
extern UniValue getnetworkinfo(const UniValue& params, bool fHelp); // ��ȡ����״̬��Ϣ
extern UniValue setmocktime(const UniValue& params, bool fHelp); // ���� mocktime
extern UniValue resendwallettransactions(const UniValue& params, bool fHelp); // ���·���Ǯ������

extern UniValue getrawtransaction(const UniValue& params, bool fHelp); // ��ȡԭʼ������Ϣ
extern UniValue listunspent(const UniValue& params, bool fHelp); // �г�δ���ѵĽ������
extern UniValue lockunspent(const UniValue& params, bool fHelp); // �ӽ���δ���ѵĽ������
extern UniValue listlockunspent(const UniValue& params, bool fHelp); // �г�������δ���ѽ������
extern UniValue createrawtransaction(const UniValue& params, bool fHelp); // ����ԭʼ����
extern UniValue decoderawtransaction(const UniValue& params, bool fHelp); // ����ԭʼ����
extern UniValue decodescript(const UniValue& params, bool fHelp); // ����ű�
extern UniValue fundrawtransaction(const UniValue& params, bool fHelp); // ����ԭʼ����
extern UniValue signrawtransaction(const UniValue& params, bool fHelp); // ǩ��ԭʼ����
extern UniValue sendrawtransaction(const UniValue& params, bool fHelp); // ����ԭʼ����
extern UniValue gettxoutproof(const UniValue& params, bool fHelp); // ��ȡ����֤��
extern UniValue verifytxoutproof(const UniValue& params, bool fHelp); // ��֤����֤��

extern UniValue getblockcount(const UniValue& params, bool fHelp); // ��ȡ��ǰ��������
extern UniValue getbestblockhash(const UniValue& params, bool fHelp); // ��ȡ��ǰ��ѿ�Ĺ�ϣ
extern UniValue getdifficulty(const UniValue& params, bool fHelp); // ��ȡ��ǰ�ڿ��Ѷ�
extern UniValue settxfee(const UniValue& params, bool fHelp); // ���ý��׷�
extern UniValue getmempoolinfo(const UniValue& params, bool fHelp); // ��ȡ�����ڴ����Ϣ
extern UniValue getrawmempool(const UniValue& params, bool fHelp); // ��ȡ�����ڴ��Ԫ��Ϣ������������
extern UniValue getblockhash(const UniValue& params, bool fHelp); // ��ȡָ�����������������ϣ
extern UniValue getblockheader(const UniValue& params, bool fHelp); // ��ȡָ�������ϣ������ͷ��Ϣ
extern UniValue getblock(const UniValue& params, bool fHelp); // ��ȡ������Ϣ
extern UniValue gettxoutsetinfo(const UniValue& params, bool fHelp); // ��ȡ�������������Ϣ
extern UniValue gettxout(const UniValue& params, bool fHelp); // ��ȡһ�ʽ�����������ϻ��ڴ���У���ϸ��
extern UniValue verifychain(const UniValue& params, bool fHelp); // ��֤���������ݿ�
extern UniValue getchaintips(const UniValue& params, bool fHelp); // ��ȡ������Ϣ
extern UniValue invalidateblock(const UniValue& params, bool fHelp); // ��Ч������
extern UniValue reconsiderblock(const UniValue& params, bool fHelp); // �ٿ�������

bool StartRPC(); // ���� RPC
void InterruptRPC();
void StopRPC(); // ֹͣ RPC
std::string JSONRPCExecBatch(const UniValue& vReq); // JSONRPC ����ִ��

#endif // BITCOIN_RPCSERVER_H
