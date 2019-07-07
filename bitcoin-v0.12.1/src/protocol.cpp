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

namespace NetMsgType { // ������Ϣ����
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
    NetMsgType::VERSION, // ���������϶Է�ʱ������ version ��Ϣ���������ӷ�ֻ���յ� version ��Ϣ��Żظ� version �� verack ��Ϣ
    NetMsgType::VERACK, // version ack �汾ȷ����Ϣ
    NetMsgType::ADDR, // ת�������ϵĽڵ��ַ�б���Ϣ
    NetMsgType::INV, // �ڵ�ͨ������Ϣ���棨advertise������ӵ�еĶ�����Ϣ����������Щ block/txs����һ�㵱����һ���¿����ת��ʱ���������ʹ���Ϣ��Ҳ������ getblocks ����Ӧ
    NetMsgType::GETDATA, // ����Ӧ�� inv ��Ϣ����ȡָ��������ͨ���ڽ��յ� inv ������ȥ����Ԫ�غ��͵��Է��ڵ��Ի�ȡδ�ж��󡣶Է��յ� getdata ��Ϣ�󣬻ظ� block �� tx ��Ϣ
    NetMsgType::MERKLEBLOCK,
    NetMsgType::GETBLOCKS, // ��ȡһ��������Ŵ� hash_start �� hash_stop �� block �б�� inv ��Ϣ������ hash_start �� hash_stop �� block �������� 500������ 500 ����ֹ��ÿ�����ֻ�ܻ�ȡ 500 ������ hash
    NetMsgType::GETHEADERS, // ��ȡ������Ŵ� hash_start �� hash_stop ����� 2000 �� block �� header ��������Ϣ���ڿ������ز�����������Ϣ�� blockchain
    NetMsgType::TX, // �ظ� getdata ��Ϣ������ tx ����
    NetMsgType::HEADERS, // ���� block ��ͷ�������� getheaders ����Ӧ
    NetMsgType::BLOCK, // �ظ� getdata ��Ϣ��������������
    NetMsgType::GETADDR, // ��������ڵ�ظ�һ�� addr ��Ϣ�����ڿ��ٸ��±��ص�ַ��
    NetMsgType::MEMPOOL, // �ռ��ڴ�ؽ���
    NetMsgType::PING, // ��������Ƿ�����
    NetMsgType::PONG, // �ظ� ping ��Ϣ
    NetMsgType::ALERT, // �����ڽڵ��ת��֪ͨ��ʹ�䴫���������磬����汾����
    NetMsgType::NOTFOUND, // �յ� getdata ��Ϣ�󣬷��ظ�֪�Է�û�з��� tx �� block
    NetMsgType::FILTERLOAD, // ���� bloom filter
    NetMsgType::FILTERADD, // ���� bloom filter
    NetMsgType::FILTERCLEAR, // ���� bloom filter
    NetMsgType::REJECT, // ��֪�Է��ڵ���һ����������Ϣ���ܾ�
    NetMsgType::SENDHEADERS // ָʾ�ڵ������� headers ��Ϣ��� inv ��Ϣ�����¿�֪ͨ��������� BIP130��Bitcoin Core 0.12.0��protocol version 70012
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
