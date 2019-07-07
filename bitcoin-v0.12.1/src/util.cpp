// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "util.h"

#include "chainparamsbase.h"
#include "random.h"
#include "serialize.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utiltime.h"

#include <stdarg.h>

#if (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
#include <pthread.h>
#include <pthread_np.h>
#endif

#ifndef WIN32
// for posix_fallocate
#ifdef __linux__

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#define _POSIX_C_SOURCE 200112L

#endif // __linux__

#include <algorithm>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#else

#ifdef _MSC_VER
#pragma warning(disable:4786)
#pragma warning(disable:4804)
#pragma warning(disable:4805)
#pragma warning(disable:4717)
#endif

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501

#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501

#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <io.h> /* for _commit */
#include <shlobj.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/foreach.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

// Work around clang compilation problem in Boost 1.46:
// /usr/include/boost/program_options/detail/config_file.hpp:163:17: error: call to function 'to_internal' that is neither visible in the template definition nor found by argument-dependent lookup
// See also: http://stackoverflow.com/questions/10020179/compilation-fail-in-boost-librairies-program-options
//           http://clang.debian.net/status.php?version=3.0&key=CANNOT_FIND_FUNCTION
namespace boost {

    namespace program_options {
        std::string to_internal(const std::string&);
    }

} // namespace boost

using namespace std;

const char * const BITCOIN_CONF_FILENAME = "bitcoin.conf"; // ���ر�Ĭ�������ļ���
const char * const BITCOIN_PID_FILENAME = "bitcoind.pid"; // ���ر�Ĭ�� pid �ļ���

map<string, string> mapArgs; // ����ѡ������в����������ļ�����ֵӳ���б�map<ѡ������ѡ��ֵ>
map<string, vector<string> > mapMultiArgs; // ����ѡ���ֵӳ���б�map<ѡ������vector<ѡ��ֵ> >
bool fDebug = false;
bool fPrintToConsole = false;
bool fPrintToDebugLog = true;
bool fDaemon = false;
bool fServer = false;
string strMiscWarning;
bool fLogTimestamps = DEFAULT_LOGTIMESTAMPS; // Ĭ��Ϊ true
bool fLogTimeMicros = DEFAULT_LOGTIMEMICROS;
bool fLogIPs = DEFAULT_LOGIPS;
volatile bool fReopenDebugLog = false; // �ٴδ���־�ļ���־��Ĭ�Ϲر�
CTranslationInterface translationInterface;

/** Init OpenSSL library multithreading support */
static CCriticalSection** ppmutexOpenSSL;
void locking_callback(int mode, int i, const char* file, int line) NO_THREAD_SAFETY_ANALYSIS
{
    if (mode & CRYPTO_LOCK) {
        ENTER_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    } else {
        LEAVE_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    }
}

// Init
class CInit
{
public:
    CInit()
    {
        // Init OpenSSL library multithreading support
        ppmutexOpenSSL = (CCriticalSection**)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(CCriticalSection*));
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            ppmutexOpenSSL[i] = new CCriticalSection();
        CRYPTO_set_locking_callback(locking_callback);

        // OpenSSL can optionally load a config file which lists optional loadable modules and engines.
        // We don't use them so we don't require the config. However some of our libs may call functions
        // which attempt to load the config file, possibly resulting in an exit() or crash if it is missing
        // or corrupt. Explicitly tell OpenSSL not to try to load the file. The result for our libs will be
        // that the config appears to have been loaded and there are no modules/engines available.
        OPENSSL_no_config();

#ifdef WIN32
        // Seed OpenSSL PRNG with current contents of the screen
        RAND_screen();
#endif

        // Seed OpenSSL PRNG with performance counter
        RandAddSeed();
    }
    ~CInit()
    {
        // Securely erase the memory used by the PRNG
        RAND_cleanup();
        // Shutdown OpenSSL library multithreading support
        CRYPTO_set_locking_callback(NULL);
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            delete ppmutexOpenSSL[i];
        OPENSSL_free(ppmutexOpenSSL);
    }
}
instance_of_cinit;

/**
 * LogPrintf() has been broken a couple of times now
 * by well-meaning people adding mutexes in the most straightforward way.
 * It breaks because it may be called by global destructors during shutdown.
 * Since the order of destruction of static/global objects is undefined,
 * defining a mutex as a global object doesn't work (the mutex gets
 * destroyed, and then some later destructor calls OutputDebugStringF,
 * maybe indirectly, and you get a core dump at shutdown trying to lock
 * the mutex).
 */

static boost::once_flag debugPrintInitFlag = BOOST_ONCE_INIT;

/**
 * We use boost::call_once() to make sure mutexDebugLog and
 * vMsgsBeforeOpenLog are initialized in a thread-safe manner.
 *
 * NOTE: fileout, mutexDebugLog and sometimes vMsgsBeforeOpenLog
 * are leaked on exit. This is ugly, but will be cleaned up by
 * the OS/libc. When the shutdown sequence is fully audited and
 * tested, explicit destruction of these objects can be implemented.
 */ // ����ʹ�� boost::call_once() ȷ�� mutexDebugLog �� vMsgsBeforeOpenLog ���̰߳�ȫ�ķ�ʽ��ʼ����
static FILE* fileout = NULL; // ��־�ļ�ָ��
static boost::mutex* mutexDebugLog = NULL; // ��־�ļ���
static list<string> *vMsgsBeforeOpenLog; // ����־�ļ�ǰ����Ϣ����

static int FileWriteStr(const std::string &str, FILE *fp)
{
    return fwrite(str.data(), 1, str.size(), fp); // д���ַ������ļ�ָ��������ļ�
}

static void DebugPrintInit() // ��ʼ��������־�ļ���
{
    assert(mutexDebugLog == NULL); // ��������־��Ϊ��
    mutexDebugLog = new boost::mutex(); // �½�һ��������
    vMsgsBeforeOpenLog = new list<string>; // �½�һ���ַ������͵�����
}

void OpenDebugLog()
{
    boost::call_once(&DebugPrintInit, debugPrintInitFlag); // ȷ��ִֻ�� DebugPrintInit() һ��
    boost::mutex::scoped_lock scoped_lock(*mutexDebugLog); // ����

    assert(fileout == NULL); // �ļ�ָ���⣬ȷ��δ��ʼ��
    assert(vMsgsBeforeOpenLog); // ȷ������־�ļ�ǰ����Ϣ�������
    boost::filesystem::path pathDebug = GetDataDir() / "debug.log"; // ��ȡ�����ļ�λ��
    fileout = fopen(pathDebug.string().c_str(), "a"); // ��׷��ֻд�ķ�ʽ�򿪣����ļ��������򴴽�
    if (fileout) setbuf(fileout, NULL); // unbuffered // �����޻���

    // dump buffered messages from before we opened the log // ���������Ǵ���־ǰ�������Ϣ
    while (!vMsgsBeforeOpenLog->empty()) { // ����Ϣ����ǿգ�����������
        FileWriteStr(vMsgsBeforeOpenLog->front(), fileout); // ��һ����Ϣ�ַ���д����־�ļ�
        vMsgsBeforeOpenLog->pop_front(); // ����ͷ����
    }

    delete vMsgsBeforeOpenLog; // ɾ��������
    vMsgsBeforeOpenLog = NULL; // ָ���ÿգ���ֹ����Ұָ��
}

bool LogAcceptCategory(const char* category)
{
    if (category != NULL) // �����ͷǿ�
    {
        if (!fDebug) // ������ѡ��δ����
            return false; // ֱ�ӷ��� false

        // Give each thread quick access to -debug settings. // ��ÿ���߳̿��ٷ��� -debug ѡ�����á�
        // This helps prevent issues debugging global destructors, // �������ڷ�ֹ����ȫ���������������⣬
        // where mapMultiArgs might be deleted before another // mapMultiArgs ��������һ��ȫ����������
        // global destructor calls LogPrint() // ���� LogPrint() ֮ǰ��ɾ��
        static boost::thread_specific_ptr<set<string> > ptrCategory; // �ֲ߳̾��洢��TLS��Ϊÿ���̶߳���
        if (ptrCategory.get() == NULL) // ��ʼΪ��
        {
            const vector<string>& categories = mapMultiArgs["-debug"]; // ��ȡ����ѡ��ָ����ֵ���������ݣ����������б�
            ptrCategory.reset(new set<string>(categories.begin(), categories.end())); // ��ȡ�����б�ÿ��Ԫ�صĵ�ַ���� TLS ��
            // thread_specific_ptr automatically deletes the set when the thread ends.
        } // thread_specific_ptr ���߳̽���ʱ�Զ�ɾ���ü��ϡ�RAII ������
        const set<string>& setCategories = *ptrCategory.get(); // ��ȡ����ַ������ϵ�����

        // if not debugging everything and not debugging specific category, LogPrint does nothing. // ���������ȫ�����ݶ������ض����LogPrint ʲôҲ������
        if (setCategories.count(string("")) == 0 && // ������к��пմ�
            setCategories.count(string("1")) == 0 && // �Һ����ַ��� ��1��
            setCategories.count(string(category)) == 0) // �Һ���ָ�����
            return false; // ֱ�ӷ��� false
    }
    return true; // ���� true
}

/**
 * fStartedNewLine is a state variable held by the calling context that will
 * suppress printing of the timestamp when multiple calls are made that don't
 * end in a newline. Initialize it to true, and hold it, in the calling context.
 */ // fStartedNewLine ��һ�����������ı����״̬�����������ڶ�ε��ò��Ի��з�����ʱ��ֹ��ӡʱ�������ʼ��Ϊ true�����ڵ����������б����ֵ��
static std::string LogTimestampStr(const std::string &str, bool *fStartedNewLine)
{
    string strStamped; // �������ʱ������ַ���

    if (!fLogTimestamps) // ��¼ʱ�����־��Ϊ false
        return str; // ֱ�ӷ��ظ��ַ���

    if (*fStartedNewLine) { // ���б�־��Ĭ��Ϊ true
        int64_t nTimeMicros = GetLogTimeMicros(); // ��ȡ��ǰʱ�䣬΢��
        strStamped = DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nTimeMicros/1000000); // ת��Ϊ�룬����ʽ������ʱ���ַ���
        if (fLogTimeMicros) // ����¼΢��ʱ��
            strStamped += strprintf(".%06d", nTimeMicros%1000000); // ׷��΢�뵽ʱ���
        strStamped += ' ' + str; // �ո����ƴ���ַ���
    } else // ����
        strStamped = str; // ����ʱ���

    if (!str.empty() && str[str.size()-1] == '\n') // ���ַ����ǿ� �� ���һ���ַ�Ϊ���з�
        *fStartedNewLine = true; // ���б�־��Ϊ true
    else // ���ַ���Ϊ��
        *fStartedNewLine = false; // ���б�־��Ϊ false

    return strStamped; // ���ش���ʱ������ַ���
}

int LogPrintStr(const std::string &str)
{
    int ret = 0; // Returns total number of characters written // ����д���ַ�������
    static bool fStartedNewLine = true; // ��ʼ�µ�һ�б�־����ʼ��Ϊ true

    string strTimestamped = LogTimestampStr(str, &fStartedNewLine); // ���ַ�������ʱ���

    if (fPrintToConsole) // �����������̨ѡ���
    {
        // print to console // ���������̨
        ret = fwrite(strTimestamped.data(), 1, strTimestamped.size(), stdout); // ������д���׼���
        fflush(stdout); // ˢ�±�׼���
    }
    else if (fPrintToDebugLog) // �������������־ѡ���
    {
        boost::call_once(&DebugPrintInit, debugPrintInitFlag); // ע��ֻ����һ�ε��Դ�ӡ��ʼ��
        boost::mutex::scoped_lock scoped_lock(*mutexDebugLog); // ������

        // buffer if we haven't opened the log yet // ������ǻ�δ����־�����л���
        if (fileout == NULL) { // ���ļ�ָ��Ϊ��
            assert(vMsgsBeforeOpenLog); // �����Ϣ�����Ѵ������
            ret = strTimestamped.length(); // ��ȡ����ʱ������ַ�������
            vMsgsBeforeOpenLog->push_back(strTimestamped); // �������Ϣ����
        }
        else // ���Ѿ���
        {
            // reopen the log file, if requested // ���������ٴδ���־�ļ�
            if (fReopenDebugLog) { // ��ָ�����ٴδ���־�ļ�
                fReopenDebugLog = false; // �ñ�־����Ϊ false
                boost::filesystem::path pathDebug = GetDataDir() / "debug.log"; // ��ȡ��־�ļ���·��
                if (freopen(pathDebug.string().c_str(),"a",fileout) != NULL) // �ٴδ���־�ļ�����׷�ӵķ�ʽ��
                    setbuf(fileout, NULL); // unbuffered // �رո��ļ�ָ��Ļ������
            }

            ret = FileWriteStr(strTimestamped, fileout); // �Ѵ���ʱ������ַ���д����־�ļ�
        }
    }
    return ret; // ����д�������־�ļ����ַ�����
}

/** Interpret string as boolean, for argument parsing */
static bool InterpretBool(const std::string& strValue) // ���ַ���ת��Ϊ�����ͣ����ڲ�������
{
    if (strValue.empty()) // ��Ϊ�մ�
        return true; // ���� true����ʾָ����ѡ��δָ��ֵʱ����ֵĬ��Ϊ true
    return (atoi(strValue) != 0); // �����ڷ���ʱת��Ϊ��Ӧ������
}

/** Turn -noX into -X=0 */ // ת�� -noX Ϊ -X=0
static void InterpretNegativeSetting(std::string& strKey, std::string& strValue)
{
    if (strKey.length()>3 && strKey[0]=='-' && strKey[1]=='n' && strKey[2]=='o') // ��ѡ�������ȴ��� 3����������ʾ����
    {
        strKey = "-" + strKey.substr(3); // �ع�ѡ����
        strValue = InterpretBool(strValue) ? "0" : "1"; // ����ѡ��ֵ
    }
}

void ParseParameters(int argc, const char* const argv[]) // 3.1.0.���������в���
{
    mapArgs.clear(); // 1.�������ѡ�ֵӳ���б�
    mapMultiArgs.clear(); // �������ѡ���ֵӳ���б�

    for (int i = 1; i < argc; i++) // 2.�ӵ�һ�������в�����ʼ�����������в���ָ������
    {
        std::string str(argv[i]); // 2.1.��ȡһ�����������ѡ����=ѡ��ֵ
        std::string strValue; // ���ڱ���ѡ��ֵ
        size_t is_index = str.find('='); // �ҵ��Ⱥŵ�λ��
        if (is_index != std::string::npos) // �����ڵȺ�
        {
            strValue = str.substr(is_index+1); // ��ȡѡ��ֵ�Ӵ�
            str = str.substr(0, is_index); // ��ȡѡ�����Ӵ�
        }
#ifdef WIN32 // 2.2.windows ƽ̨
        boost::to_lower(str); // ѡ����ת��ΪСд
        if (boost::algorithm::starts_with(str, "/")) // ��ѡ�������ַ� "/" ��ͷ
            str = "-" + str.substr(1); // �滻��ͷΪ�ַ� "-"
#endif

        if (str[0] != '-') // 2.3.��ѡ���������ַ� '-' ��ͷ
            break; // ������������ѡ��

        // Interpret --foo as -foo. // ת�� --foo Ϊ -foo��
        // If both --foo and -foo are set, the last takes effect. // ��ͬʱ������ --foo �� -foo���������Ч��
        if (str.length() > 1 && str[1] == '-') // ��ѡ�������ȴ��� 1 �� �ڶ����ַ�Ϊ '-'
            str = str.substr(1); // ������һ���ַ� '-'
        InterpretNegativeSetting(str, strValue); // 2.4.ת�� -no ѡ��������

        mapArgs[str] = strValue; // 2.5.��������ѡ�ֵӳ���б�
        mapMultiArgs[str].push_back(strValue); // ��������ѡ���ֵӳ���б�
    } // ѭ����ֱ�����������в����������
}

std::string GetArg(const std::string& strArg, const std::string& strDefault)
{
    if (mapArgs.count(strArg))
        return mapArgs[strArg];
    return strDefault;
}

int64_t GetArg(const std::string& strArg, int64_t nDefault)
{
    if (mapArgs.count(strArg))
        return atoi64(mapArgs[strArg]);
    return nDefault;
}

bool GetBoolArg(const std::string& strArg, bool fDefault)
{
    if (mapArgs.count(strArg)) // ����ѡ�����
        return InterpretBool(mapArgs[strArg]); // �������Ӧ��ֵ��ת��Ϊ�����ͣ�
    return fDefault; // ���򷵻�Ĭ��ֵ
}

bool SoftSetArg(const std::string& strArg, const std::string& strValue)
{
    if (mapArgs.count(strArg)) // ����ѡ���Ѿ����ڣ����ã�
        return false; // ֱ�ӷ��� false
    mapArgs[strArg] = strValue; // ��������Ϊָ����ֵ
    return true; // ���� true����ʾ���óɹ�
}

bool SoftSetBoolArg(const std::string& strArg, bool fValue)
{
    if (fValue)
        return SoftSetArg(strArg, std::string("1"));
    else
        return SoftSetArg(strArg, std::string("0"));
}

static const int screenWidth = 79;
static const int optIndent = 2;
static const int msgIndent = 7;

std::string HelpMessageGroup(const std::string &message) {
    return std::string(message) + std::string("\n\n");
}

std::string HelpMessageOpt(const std::string &option, const std::string &message) {
    return std::string(optIndent,' ') + std::string(option) +
           std::string("\n") + std::string(msgIndent,' ') +
           FormatParagraph(message, screenWidth - msgIndent, msgIndent) +
           std::string("\n\n");
}

static std::string FormatException(const std::exception* pex, const char* pszThread)
{
#ifdef WIN32
    char pszModule[MAX_PATH] = "";
    GetModuleFileNameA(NULL, pszModule, sizeof(pszModule));
#else
    const char* pszModule = "bitcoin";
#endif
    if (pex)
        return strprintf(
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, pszThread);
    else
        return strprintf(
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
}

void PrintExceptionContinue(const std::exception* pex, const char* pszThread)
{
    std::string message = FormatException(pex, pszThread);
    LogPrintf("\n\n************************\n%s\n", message);
    fprintf(stderr, "\n\n************************\n%s\n", message.c_str());
}

boost::filesystem::path GetDefaultDataDir()
{
    namespace fs = boost::filesystem;
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\Bitcoin
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\Bitcoin
    // Mac: ~/Library/Application Support/Bitcoin
    // Unix: ~/.bitcoin
#ifdef WIN32
    // Windows
    return GetSpecialFolderPath(CSIDL_APPDATA) / "Bitcoin";
#else // UNIX/Linux
    fs::path pathRet;
    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
#ifdef MAC_OSX
    // Mac
    pathRet /= "Library/Application Support";
    TryCreateDirectory(pathRet);
    return pathRet / "Bitcoin";
#else
    // Unix
    return pathRet / ".bitcoin";
#endif
#endif
}

static boost::filesystem::path pathCached; // ·������
static boost::filesystem::path pathCachedNetSpecific; // ָ�������·������
static CCriticalSection csPathCached; // ·��������

const boost::filesystem::path &GetDataDir(bool fNetSpecific)
{
    namespace fs = boost::filesystem;

    LOCK(csPathCached); // 1.·����������

    fs::path &path = fNetSpecific ? pathCachedNetSpecific : pathCached; // 2.false

    // This can be called during exceptions by LogPrintf(), so we cache the // ��������쳣�ڼ�ͨ�� LogPrintf() ���ã�
    // value so we don't have to do memory allocations after that. // �������ǻ����ֵ�����������ǲ�����֮������ڴ���䡣
    if (!path.empty()) // 3.��·���ǿ�
        return path; // ֱ�ӷ�������Ŀ¼��·��

    if (mapArgs.count("-datadir")) { // 4.������ָ��������Ŀ¼��λ��
        path = fs::system_complete(mapArgs["-datadir"]); // ��ȡָ����·��
        if (!fs::is_directory(path)) { // ����·������Ŀ¼
            path = ""; // �ÿ�
            return path; // ����
        }
    } else { // ��δָ������Ŀ¼λ��
        path = GetDefaultDataDir(); // ��ȡĬ�ϵ�����Ŀ¼·��
    }
    if (fNetSpecific) // false // 5.��ָ�����ض�����
        path /= BaseParams().DataDir(); // ·��ƴ�ӣ���ȡ��ͬ���������Ŀ¼

    fs::create_directories(path); // 6.������Ŀ¼

    return path; // 7.��������Ŀ¼��·��
}

void ClearDatadirCache()
{
    pathCached = boost::filesystem::path(); // ·�������ÿ�
    pathCachedNetSpecific = boost::filesystem::path(); // ָ�������·�������ÿ�
}

boost::filesystem::path GetConfigFile()
{
    boost::filesystem::path pathConfigFile(GetArg("-conf", BITCOIN_CONF_FILENAME)); // ��ȡ�����ļ���ָ��/Ĭ�ϣ���
    if (!pathConfigFile.is_complete()) // �����ļ����Ƿ�����
        pathConfigFile = GetDataDir(false) / pathConfigFile; // ·��ƴ�ӣ���ȡ�����ļ�·��

    return pathConfigFile; // ���������ļ�·��
}

void ReadConfigFile(map<string, string>& mapSettingsRet,
                    map<string, vector<string> >& mapMultiSettingsRet)
{
    boost::filesystem::ifstream streamConfig(GetConfigFile()); // 1.��ȡ�����ļ�·���������ļ�����������
    if (!streamConfig.good()) // �����������û�������ļ�
        return; // No bitcoin.conf file is OK

    set<string> setOptions; // 2.ѡ��
    setOptions.insert("*"); // ���� "*"�����ڹ��������ļ��д��� '*' ����

    for (boost::program_options::detail::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it) // 3.���������ļ�������
    {
        // Don't overwrite existing settings so command line settings override bitcoin.conf // �������Ѵ��ڵ����ã�������������ûḲ�������ļ�����
        string strKey = string("-") + it->string_key; // 3.1.ѡ����
        string strValue = it->value[0]; // ѡ��ֵ
        InterpretNegativeSetting(strKey, strValue); // �� -noX ת��Ϊ -X=0
        if (mapSettingsRet.count(strKey) == 0) // 3.2.������ѡ�ֵӳ���б��в�����ѡ��
            mapSettingsRet[strKey] = strValue; // �����б�
        mapMultiSettingsRet[strKey].push_back(strValue); // �����ֵӳ���б�
    }
    // If datadir is changed in .conf file: // �������Ŀ¼�������ļ��иı�
    ClearDatadirCache(); // 4.��������Ŀ¼����
}

#ifndef WIN32
boost::filesystem::path GetPidFile()
{
    boost::filesystem::path pathPidFile(GetArg("-pid", BITCOIN_PID_FILENAME)); // ��ȡ pid �ļ���
    if (!pathPidFile.is_complete()) pathPidFile = GetDataDir() / pathPidFile; // pid �ļ�·��ƴ��
    return pathPidFile; // ���� pid �ļ�·����
}

void CreatePidFile(const boost::filesystem::path &path, pid_t pid)
{
    FILE* file = fopen(path.string().c_str(), "w"); // ��ֻд��ʽ���ļ��������������½�
    if (file) // �����ɹ�
    {
        fprintf(file, "%d\n", pid); // ��� pid �����ļ�
        fclose(file); // �ر��ļ�
    }
}
#endif

bool RenameOver(boost::filesystem::path src, boost::filesystem::path dest)
{
#ifdef WIN32
    return MoveFileExA(src.string().c_str(), dest.string().c_str(),
                       MOVEFILE_REPLACE_EXISTING) != 0;
#else
    int rc = std::rename(src.string().c_str(), dest.string().c_str());
    return (rc == 0);
#endif /* WIN32 */
}

/**
 * Ignores exceptions thrown by Boost's create_directory if the requested directory exists.
 * Specifically handles case where path p exists, but it wasn't possible for the user to
 * write to the parent directory.
 */
bool TryCreateDirectory(const boost::filesystem::path& p)
{
    try
    {
        return boost::filesystem::create_directory(p); // ����Ŀ¼ p
    } catch (const boost::filesystem::filesystem_error&) {
        if (!boost::filesystem::exists(p) || !boost::filesystem::is_directory(p)) // Ŀ¼ p ������ �� ���ڵ���Ŀ¼����
            throw; // �׳��쳣
    }

    // create_directory didn't create the directory, it had to have existed already
    return false;
}

void FileCommit(FILE *fileout)
{
    fflush(fileout); // harmless if redundantly called // ˢ�����ݵ�����
#ifdef WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(fileout));
    FlushFileBuffers(hFile);
#else
    #if defined(__linux__) || defined(__NetBSD__)
    fdatasync(fileno(fileout));
    #elif defined(__APPLE__) && defined(F_FULLFSYNC)
    fcntl(fileno(fileout), F_FULLFSYNC, 0);
    #else
    fsync(fileno(fileout));
    #endif
#endif
}

bool TruncateFile(FILE *file, unsigned int length) {
#if defined(WIN32) // windows
    return _chsize(_fileno(file), length) == 0;
#else // Unix/Linux
    return ftruncate(fileno(file), length) == 0;
#endif
}

/**
 * this function tries to raise the file descriptor limit to the requested number.
 * It returns the actual file descriptor limit (which may be more or less than nMinFD)
 */
int RaiseFileDescriptorLimit(int nMinFD) {
#if defined(WIN32)
    return 2048;
#else
    struct rlimit limitFD;
    if (getrlimit(RLIMIT_NOFILE, &limitFD) != -1) { // RLIMIT_NOFILE �ں�Ĭ�� 1024����ʾÿ����������ܴ򿪵��ļ�������������linux-4.16.4 src �ж���Ϊ 5��6��7
        if (limitFD.rlim_cur < (rlim_t)nMinFD) { // rlim_cur Ϊ Soft limit ���ں˶�һ��������ʹ�õ���Դ�����ƣ��� rlim_max Ϊ Hard limit �� Soft limit ������
            limitFD.rlim_cur = nMinFD;
            if (limitFD.rlim_cur > limitFD.rlim_max)
                limitFD.rlim_cur = limitFD.rlim_max;
            setrlimit(RLIMIT_NOFILE, &limitFD);
            getrlimit(RLIMIT_NOFILE, &limitFD);
        }
        return limitFD.rlim_cur; // ���ص����������������
    }
    return nMinFD; // getrlimit failed, assume it's fine
#endif
}

/**
 * this function tries to make a particular range of a file allocated (corresponding to disk space)
 * it is advisory, and the range specified in the arguments will never contain live data
 */
void AllocateFileRange(FILE *file, unsigned int offset, unsigned int length) {
#if defined(WIN32)
    // Windows-specific version
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(file));
    LARGE_INTEGER nFileSize;
    int64_t nEndPos = (int64_t)offset + length;
    nFileSize.u.LowPart = nEndPos & 0xFFFFFFFF;
    nFileSize.u.HighPart = nEndPos >> 32;
    SetFilePointerEx(hFile, nFileSize, 0, FILE_BEGIN);
    SetEndOfFile(hFile);
#elif defined(MAC_OSX)
    // OSX specific version
    fstore_t fst;
    fst.fst_flags = F_ALLOCATECONTIG;
    fst.fst_posmode = F_PEOFPOSMODE;
    fst.fst_offset = 0;
    fst.fst_length = (off_t)offset + length;
    fst.fst_bytesalloc = 0;
    if (fcntl(fileno(file), F_PREALLOCATE, &fst) == -1) {
        fst.fst_flags = F_ALLOCATEALL;
        fcntl(fileno(file), F_PREALLOCATE, &fst);
    }
    ftruncate(fileno(file), fst.fst_length);
#elif defined(__linux__)
    // Version using posix_fallocate
    off_t nEndPos = (off_t)offset + length;
    posix_fallocate(fileno(file), 0, nEndPos);
#else
    // Fallback version
    // TODO: just write one byte per block
    static const char buf[65536] = {};
    fseek(file, offset, SEEK_SET);
    while (length > 0) {
        unsigned int now = 65536;
        if (length < now)
            now = length;
        fwrite(buf, 1, now, file); // allowed to fail; this function is advisory anyway
        length -= now;
    }
#endif
}

void ShrinkDebugFile()
{
    // Scroll debug.log if it's getting too big // �������̫�󣬻ع� debug.log
    boost::filesystem::path pathLog = GetDataDir() / "debug.log"; // ��ȡ��־λ��
    FILE* file = fopen(pathLog.string().c_str(), "r"); // ��ֻ����ʽ����־
    if (file && boost::filesystem::file_size(pathLog) > 10 * 1000000) // ����־�ļ���С����Լ 10MiB
    {
        // Restart the file with some of the end // ʹ�ý�β��Ϣ��д�ļ�
        std::vector <char> vch(200000,0); // ���� 200KB ��������ʼ��Ϊ 0
        fseek(file, -((long)vch.size()), SEEK_END); // �ļ�ָ����ļ�β����ǰƫ�� 200,000 ���ֽ�
        int nBytes = fread(begin_ptr(vch), 1, vch.size(), file); // ��ȡ���µ� 200KB ������־���ڴ�
        fclose(file); // �ر��ļ�

        file = fopen(pathLog.string().c_str(), "w"); // ��ֻд��ʽ���´��ļ����ļ����ڳ�������
        if (file) // ���򿪳ɹ�
        {
            fwrite(begin_ptr(vch), 1, nBytes, file); // �����µ� 200KB ������־д���ļ�
            fclose(file); // �ر��ļ�
        }
    }
    else if (file != NULL) // ���򿪳ɹ�
        fclose(file); // ֱ�ӹر��ļ�
}

#ifdef WIN32
boost::filesystem::path GetSpecialFolderPath(int nFolder, bool fCreate)
{
    namespace fs = boost::filesystem;

    char pszPath[MAX_PATH] = "";

    if(SHGetSpecialFolderPathA(NULL, pszPath, nFolder, fCreate))
    {
        return fs::path(pszPath);
    }

    LogPrintf("SHGetSpecialFolderPathA() failed, could not obtain requested path.\n");
    return fs::path("");
}
#endif

boost::filesystem::path GetTempPath() {
#if BOOST_FILESYSTEM_VERSION == 3
    return boost::filesystem::temp_directory_path();
#else
    // TODO: remove when we don't support filesystem v2 anymore
    boost::filesystem::path path;
#ifdef WIN32
    char pszPath[MAX_PATH] = "";

    if (GetTempPathA(MAX_PATH, pszPath))
        path = boost::filesystem::path(pszPath);
#else
    path = boost::filesystem::path("/tmp");
#endif
    if (path.empty() || !boost::filesystem::is_directory(path)) {
        LogPrintf("GetTempPath(): failed to find temp path\n");
        return boost::filesystem::path("");
    }
    return path;
#endif
}

void runCommand(const std::string& strCommand)
{
    int nErr = ::system(strCommand.c_str()); // ִ������ bash ����
    if (nErr)
        LogPrintf("runCommand error: system(%s) returned %d\n", strCommand, nErr);
}

void RenameThread(const char* name)
{
#if defined(PR_SET_NAME) // Linux
    // Only the first 15 characters are used (16 - NUL terminator) // ����ǰ 15 ���ַ���16 - NULL ��ֹ����
    ::prctl(PR_SET_NAME, name, 0, 0, 0); // �����߳���Ϊ name���������� 15 ���ַ��Ĳ��ֻᱻ��Ĭ�ض�
#elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)) // UNIX
    pthread_set_name_np(pthread_self(), name);

#elif defined(MAC_OSX) // Apple
    pthread_setname_np(name);
#else
    // Prevent warnings for unused parameters... // ��ֹ��δʹ�õĲ����ľ���
    (void)name; // תΪ��
#endif
}

void SetupEnvironment()
{
    // On most POSIX systems (e.g. Linux, but not BSD) the environment's locale // �ڶ���ϵͳ�����磺Linux������ BSD���ϣ��������������ã�������ص㣩������Ч��
    // may be invalid, in which case the "C" locale is used as fallback. // ��C�� �����������ں󱸡�
#if !defined(WIN32) && !defined(MAC_OSX) && !defined(__FreeBSD__) && !defined(__OpenBSD__) // ���ǣ�Ϊ���壩 WIN32��MAC_OSX��__FreeBSD__��__OpenBSD__
    try { // 1.���Խ��б�����������
        std::locale(""); // Raises a runtime error if current locale is invalid // ����ǰ����������Ч����������ʱ����
    } catch (const std::runtime_error&) {
        setenv("LC_ALL", "C", 1); // POSIX �ӿڣ����˵� ��C�� ��������
    }
#endif
    // The path locale is lazy initialized and to avoid deinitialization errors // ·�����������������صģ���Ϊ�˱����ڶ��̻߳����еķ���ʼ������
    // in multithreading environments, it is set explicitly by the main thread. // ��ͨ�����߳���ʾ���á�
    // A dummy locale is used to extract the internal default locale, used by // ������������ͨ��ʹ�� boost::filesystem::path ������ȡ�ڲ�Ĭ�ϵ��������ã�
    // boost::filesystem::path, which is then used to explicitly imbue the path. // Ȼ��������ʾ���·����
    std::locale loc = boost::filesystem::path::imbue(std::locale::classic()); // 2.������һ����ٵ�������ȡ��ԭ������
    boost::filesystem::path::imbue(loc); // 2.�����
}

bool SetupNetworking()
{
#ifdef WIN32
    // Initialize Windows Sockets // ��ʼ�� Windows �׽���
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR || LOBYTE(wsadata.wVersion ) != 2 || HIBYTE(wsadata.wVersion) != 2)
        return false;
#endif
    return true; // �� WIN32 ϵͳֱ�ӷ��� true
}

void SetThreadPriority(int nPriority)
{
#ifdef WIN32
    SetThreadPriority(GetCurrentThread(), nPriority);
#else // WIN32
#ifdef PRIO_THREAD
    setpriority(PRIO_THREAD, 0, nPriority);
#else // PRIO_THREAD
    setpriority(PRIO_PROCESS, 0, nPriority);
#endif // PRIO_THREAD
#endif // WIN32
}

int GetNumCores()
{
#if BOOST_VERSION >= 105600
    return boost::thread::physical_concurrency();
#else // Must fall back to hardware_concurrency, which unfortunately counts virtual cores
    return boost::thread::hardware_concurrency();
#endif
}

