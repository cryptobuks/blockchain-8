// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"

#include "util.h"
#include "utilstrencodings.h"

#ifndef WIN32
# include <arpa/inet.h>
#endif

namespace NetMsgType { // 网络消息类型
const char *VERSION="version";
const char *VERACK="verack";
const char *ADDR="addr";
const char *INV="inv";
const char *GETDATA="getdata";
const char *MERKLEBLOCK="merkleblock";
const char *GETBLOCKS="getblocks";
const char *GETHEADERS="getheaders";
const char *TX="tx";
const char *HEADERS="headers";
const char *BLOCK="block";
const char *GETADDR="getaddr";
const char *MEMPOOL="mempool";
const char *PING="ping";
const char *PONG="pong";
const char *ALERT="alert";
const char *NOTFOUND="notfound";
const char *FILTERLOAD="filterload";
const char *FILTERADD="filteradd";
const char *FILTERCLEAR="filterclear";
const char *REJECT="reject";
const char *SENDHEADERS="sendheaders";
};

static const char* ppszTypeName[] =
{
    "ERROR", // Should never occur
    NetMsgType::TX,
    NetMsgType::BLOCK,
    "filtered block" // Should never occur
};

/** All known message types. Keep this in the same order as the list of
 * messages above and in protocol.h.
 */
const static std::string allNetMessageTypes[] = {
    NetMsgType::VERSION, // 主动连接上对方时，发送 version 消息。被动连接方只有收到 version 消息后才回复 version 和 verack 消息
    NetMsgType::VERACK, // version ack 版本确认消息
    NetMsgType::ADDR, // 转发网络上的节点地址列表消息
    NetMsgType::INV, // 节点通过此消息宣告（advertise）它所拥有的对象消息。“我有这些 block/txs”，一般当产生一个新块或交易转发时会主动发送此消息，也可用于 getblocks 的响应
    NetMsgType::GETDATA, // 用于应答 inv 消息来获取指定对象，它通常在接收到 inv 包并滤去已有元素后发送到对方节点以获取未有对象。对方收到 getdata 消息后，回复 block 或 tx 消息
    NetMsgType::MERKLEBLOCK,
    NetMsgType::GETBLOCKS, // 获取一个包含编号从 hash_start 到 hash_stop 的 block 列表的 inv 消息。若从 hash_start 到 hash_stop 的 block 数超过了 500，则在 500 处截止，每次最多只能获取 500 条区块 hash
    NetMsgType::GETHEADERS, // 获取包含编号从 hash_start 到 hash_stop 的最多 2000 个 block 的 header 包。此消息用于快速下载不包含交易信息的 blockchain
    NetMsgType::TX, // 回复 getdata 消息，发送 tx 内容
    NetMsgType::HEADERS, // 返回 block 的头部，用于 getheaders 的响应
    NetMsgType::BLOCK, // 回复 getdata 消息，发送区块内容
    NetMsgType::GETADDR, // 主动请求节点回复一个 addr 消息，用于快速更新本地地址库
    NetMsgType::MEMPOOL, // 收集内存池交易
    NetMsgType::PING, // 检查连接是否在线
    NetMsgType::PONG, // 回复 ping 消息
    NetMsgType::ALERT, // 用于在节点间转发通知，使其传遍整个网络，比如版本升级
    NetMsgType::NOTFOUND, // 收到 getdata 消息后，返回告知对方没有发现 tx 或 block
    NetMsgType::FILTERLOAD, // 用于 bloom filter
    NetMsgType::FILTERADD, // 用于 bloom filter
    NetMsgType::FILTERCLEAR, // 用于 bloom filter
    NetMsgType::REJECT, // 告知对方节点上一（几）个消息被拒绝
    NetMsgType::SENDHEADERS // 指示节点优先用 headers 消息替代 inv 消息接收新块通知。新添加于 BIP130、Bitcoin Core 0.12.0、protocol version 70012
};
const static std::vector<std::string> allNetMessageTypesVec(allNetMessageTypes, allNetMessageTypes+ARRAYLEN(allNetMessageTypes));

CMessageHeader::CMessageHeader(const MessageStartChars& pchMessageStartIn)
{
    memcpy(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    nMessageSize = -1;
    nChecksum = 0;
}

CMessageHeader::CMessageHeader(const MessageStartChars& pchMessageStartIn, const char* pszCommand, unsigned int nMessageSizeIn)
{
    memcpy(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    strncpy(pchCommand, pszCommand, COMMAND_SIZE);
    nMessageSize = nMessageSizeIn;
    nChecksum = 0;
}

std::string CMessageHeader::GetCommand() const
{
    return std::string(pchCommand, pchCommand + strnlen(pchCommand, COMMAND_SIZE));
}

bool CMessageHeader::IsValid(const MessageStartChars& pchMessageStartIn) const
{
    // Check start string
    if (memcmp(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE) != 0)
        return false;

    // Check the command string for errors
    for (const char* p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; p1++)
    {
        if (*p1 == 0)
        {
            // Must be all zeros after the first zero
            for (; p1 < pchCommand + COMMAND_SIZE; p1++)
                if (*p1 != 0)
                    return false;
        }
        else if (*p1 < ' ' || *p1 > 0x7E)
            return false;
    }

    // Message size
    if (nMessageSize > MAX_SIZE)
    {
        LogPrintf("CMessageHeader::IsValid(): (%s, %u bytes) nMessageSize > MAX_SIZE\n", GetCommand(), nMessageSize);
        return false;
    }

    return true;
}



CAddress::CAddress() : CService()
{
    Init();
}

CAddress::CAddress(CService ipIn, uint64_t nServicesIn) : CService(ipIn)
{
    Init();
    nServices = nServicesIn;
}

void CAddress::Init()
{
    nServices = NODE_NETWORK;
    nTime = 100000000;
}

CInv::CInv()
{
    type = 0;
    hash.SetNull();
}

CInv::CInv(int typeIn, const uint256& hashIn)
{
    type = typeIn;
    hash = hashIn;
}

CInv::CInv(const std::string& strType, const uint256& hashIn)
{
    unsigned int i;
    for (i = 1; i < ARRAYLEN(ppszTypeName); i++)
    {
        if (strType == ppszTypeName[i])
        {
            type = i;
            break;
        }
    }
    if (i == ARRAYLEN(ppszTypeName))
        throw std::out_of_range(strprintf("CInv::CInv(string, uint256): unknown type '%s'", strType));
    hash = hashIn;
}

bool operator<(const CInv& a, const CInv& b)
{
    return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
}

bool CInv::IsKnownType() const
{
    return (type >= 1 && type < (int)ARRAYLEN(ppszTypeName)); // type < 4
}

const char* CInv::GetCommand() const
{
    if (!IsKnownType())
        throw std::out_of_range(strprintf("CInv::GetCommand(): type=%d unknown type", type));
    return ppszTypeName[type];
}

std::string CInv::ToString() const
{
    return strprintf("%s %s", GetCommand(), hash.ToString());
}

const std::vector<std::string> &getAllNetMessageTypes()
{
    return allNetMessageTypesVec;
}
