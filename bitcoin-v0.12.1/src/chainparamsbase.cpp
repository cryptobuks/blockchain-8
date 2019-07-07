// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparamsbase.h"

#include "tinyformat.h"
#include "util.h"

#include <assert.h>

const std::string CBaseChainParams::MAIN = "main";
const std::string CBaseChainParams::TESTNET = "test";
const std::string CBaseChainParams::REGTEST = "regtest";

void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp)
{
    strUsage += HelpMessageGroup(_("Chain selection options:"));
    strUsage += HelpMessageOpt("-testnet", _("Use the test chain"));
    if (debugHelp) {
        strUsage += HelpMessageOpt("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                                   "This is intended for regression testing tools and app development.");
    }
}

/**
 * Main network // 主网
 */
class CBaseMainParams : public CBaseChainParams
{
public:
    CBaseMainParams()
    {
        nRPCPort = 8331;//8332; // 与 bitcoin-cli 进行通讯的默认端口
    }
};
static CBaseMainParams mainParams; // 全局静态主网基础参数对象

/**
 * Testnet (v3) // 测试网（版本 3）
 */
class CBaseTestNetParams : public CBaseChainParams
{
public:
    CBaseTestNetParams()
    {
        nRPCPort = 18331;//18332;
        strDataDir = "testnet3";
    }
};
static CBaseTestNetParams testNetParams; // 全局静态测试网基础参数对象

/*
 * Regression test // 回归测试模式
 */
class CBaseRegTestParams : public CBaseChainParams
{
public:
    CBaseRegTestParams()
    {
        nRPCPort = 18331;//18332;
        strDataDir = "regtest";
    }
};
static CBaseRegTestParams regTestParams; // 全局静态回归测试网基础参数对象

static CBaseChainParams* pCurrentBaseParams = 0; // 当前选择的基础链参数对象全局静态指针

const CBaseChainParams& BaseParams()
{
    assert(pCurrentBaseParams);
    return *pCurrentBaseParams;
}

CBaseChainParams& BaseParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) // 若选择的为主链
        return mainParams; // 返回主链基础参数对象
    else if (chain == CBaseChainParams::TESTNET) // 若选择的为测试链
        return testNetParams; // 返回测试链基础参数对象
    else if (chain == CBaseChainParams::REGTEST) // 若选择的为回归测试链
        return regTestParams; // 返回回归测试链基础参数对象
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectBaseParams(const std::string& chain)
{
    pCurrentBaseParams = &BaseParams(chain); // 使当前选择的基础链参数全局静态指针指向选择的链基础参数对象
}

std::string ChainNameFromCommandLine()
{
    bool fRegTest = GetBoolArg("-regtest", false); // 回归测试模式选项，默认关闭
    bool fTestNet = GetBoolArg("-testnet", false); // 测试网选项，默认关闭

    if (fTestNet && fRegTest) // 若同时选择了测试网和回归测试模式
        throw std::runtime_error("Invalid combination of -regtest and -testnet."); // 抛出异常
    if (fRegTest) // 若选择了回归测试模式
        return CBaseChainParams::REGTEST; // 返回回归测试网名称
    if (fTestNet) // 若选择了测试网
        return CBaseChainParams::TESTNET; // 返回测试网名称
    return CBaseChainParams::MAIN; // 否则返回主网名称，默认
}

bool AreBaseParamsConfigured()
{
    return pCurrentBaseParams != NULL;
}
