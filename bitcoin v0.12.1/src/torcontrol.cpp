#include "torcontrol.h"
#include "utilstrencodings.h"
#include "net.h"
#include "util.h"
#include "crypto/hmac_sha256.h"

#include <vector>
#include <deque>
#include <set>
#include <stdlib.h>

#include <boost/function.hpp>
#include <boost/bind.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/replace.hpp>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/thread.h>

/** Default control port */ // 洋葱路由默认控制端口
const std::string DEFAULT_TOR_CONTROL = "127.0.0.1:9051";
/** Tor cookie size (from control-spec.txt) */
static const int TOR_COOKIE_SIZE = 32; // 洋葱路由 cookie 大小
/** Size of client/server nonce for SAFECOOKIE */
static const int TOR_NONCE_SIZE = 32;
/** For computing serverHash in SAFECOOKIE */
static const std::string TOR_SAFE_SERVERKEY = "Tor safe cookie authentication server-to-controller hash";
/** For computing clientHash in SAFECOOKIE */
static const std::string TOR_SAFE_CLIENTKEY = "Tor safe cookie authentication controller-to-server hash";
/** Exponential backoff configuration - initial timeout in seconds */
static const float RECONNECT_TIMEOUT_START = 1.0;
/** Exponential backoff configuration - growth factor */
static const float RECONNECT_TIMEOUT_EXP = 1.5;
/** Maximum length for lines received on TorControlConnection.
 * tor-control-spec.txt mentions that there is explicitly no limit defined to line length,
 * this is belt-and-suspenders sanity limit to prevent memory exhaustion.
 */ // 洋葱路由控制连接接收的最大行数。
static const int MAX_LINE_LENGTH = 100000; // 100,000 行

/****** Low-level TorControlConnection ********/

/** Reply from Tor, can be single or multi-line */
class TorControlReply // 来自洋葱路由的响应，一行或多行
{
public:
    TorControlReply() { Clear(); } // 无参构造函数

    int code;
    std::vector<std::string> lines; // 响应内容

    void Clear()
    {
        code = 0;
        lines.clear();
    }
};

/** Low-level handling for Tor control connection.
 * Speaks the SMTP-like protocol as defined in torspec/control-spec.txt
 */ // 洋葱路由控制连接的低级处理。说出类似 SMTP 的协议。
class TorControlConnection
{
public:
    typedef boost::function<void(TorControlConnection&)> ConnectionCB;
    typedef boost::function<void(TorControlConnection &,const TorControlReply &)> ReplyHandlerCB;

    /** Create a new TorControlConnection.
     */ // 创建一个新的洋葱路由控制连接对象。
    TorControlConnection(struct event_base *base);
    ~TorControlConnection();

    /**
     * Connect to a Tor control port.
     * target is address of the form host:port.
     * connected is the handler that is called when connection is succesfully established.
     * disconnected is a handler that is called when the connection is broken.
     * Return true on success.
     */ // 连接到洋葱路由控制端口。target 是“主机：端口”形式的地址。connected 是连接成功建立时调用的处理函数。disconnected 是连接断开时调用的处理函数。成功返回 true。
    bool Connect(const std::string &target, const ConnectionCB& connected, const ConnectionCB& disconnected);

    /**
     * Disconnect from Tor control port.
     */ // 断开洋葱路由控制端口。
    bool Disconnect();

    /** Send a command, register a handler for the reply.
     * A trailing CRLF is automatically added.
     * Return true on success.
     */ // 发送一条命令，注册响应的处理函数。自动在尾部添加回车换行 CRLF（即\r\n）
    bool Command(const std::string &cmd, const ReplyHandlerCB& reply_handler);

    /** Response handlers for async replies */ // 异步响应处理函数
    boost::signals2::signal<void(TorControlConnection &,const TorControlReply &)> async_handler;
private:
    /** Callback when ready for use */ // 用于连接准备的回调
    boost::function<void(TorControlConnection&)> connected;
    /** Callback when connection lost */ // 断开连接时的回调
    boost::function<void(TorControlConnection&)> disconnected;
    /** Libevent event base */
    struct event_base *base; // Libevent 事件基指针
    /** Connection to control socket */
    struct bufferevent *b_conn; // 连接到控制套接字
    /** Message being received */
    TorControlReply message; // 接收的信息
    /** Response handlers */ // 响应处理函数
    std::deque<ReplyHandlerCB> reply_handlers; // 处理函数队列

    /** Libevent handlers: internal */
    static void readcb(struct bufferevent *bev, void *ctx);
    static void eventcb(struct bufferevent *bev, short what, void *ctx);
};

TorControlConnection::TorControlConnection(struct event_base *base):
    base(base), b_conn(0)
{
}

TorControlConnection::~TorControlConnection()
{
    if (b_conn)
        bufferevent_free(b_conn);
}

void TorControlConnection::readcb(struct bufferevent *bev, void *ctx)
{
    TorControlConnection *self = (TorControlConnection*)ctx;
    struct evbuffer *input = bufferevent_get_input(bev);
    size_t n_read_out = 0;
    char *line;
    assert(input);
    //  If there is not a whole line to read, evbuffer_readln returns NULL
    while((line = evbuffer_readln(input, &n_read_out, EVBUFFER_EOL_CRLF)) != NULL)
    {
        std::string s(line, n_read_out);
        free(line);
        if (s.size() < 4) // Short line
            continue;
        // <status>(-|+| )<data><CRLF>
        self->message.code = atoi(s.substr(0,3));
        self->message.lines.push_back(s.substr(4));
        char ch = s[3]; // '-','+' or ' '
        if (ch == ' ') {
            // Final line, dispatch reply and clean up
            if (self->message.code >= 600) {
                // Dispatch async notifications to async handler
                // Synchronous and asynchronous messages are never interleaved
                self->async_handler(*self, self->message);
            } else {
                if (!self->reply_handlers.empty()) {
                    // Invoke reply handler with message
                    self->reply_handlers.front()(*self, self->message);
                    self->reply_handlers.pop_front();
                } else {
                    LogPrint("tor", "tor: Received unexpected sync reply %i\n", self->message.code);
                }
            }
            self->message.Clear();
        }
    }
    //  Check for size of buffer - protect against memory exhaustion with very long lines
    //  Do this after evbuffer_readln to make sure all full lines have been
    //  removed from the buffer. Everything left is an incomplete line.
    if (evbuffer_get_length(input) > MAX_LINE_LENGTH) {
        LogPrintf("tor: Disconnecting because MAX_LINE_LENGTH exceeded\n");
        self->Disconnect();
    }
}

void TorControlConnection::eventcb(struct bufferevent *bev, short what, void *ctx)
{
    TorControlConnection *self = (TorControlConnection*)ctx;
    if (what & BEV_EVENT_CONNECTED) {
        LogPrint("tor", "tor: Succesfully connected!\n");
        self->connected(*self);
    } else if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_ERROR)
            LogPrint("tor", "tor: Error connecting to Tor control socket\n");
        else
            LogPrint("tor", "tor: End of stream\n");
        self->Disconnect();
        self->disconnected(*self);
    }
}

bool TorControlConnection::Connect(const std::string &target, const ConnectionCB& connected, const ConnectionCB& disconnected)
{
    if (b_conn) // 若连接已存在
        Disconnect(); // 先断开连接
    // Parse target address:port // 解析目标端口
    struct sockaddr_storage connect_to_addr;
    int connect_to_addrlen = sizeof(connect_to_addr);
    if (evutil_parse_sockaddr_port(target.c_str(),
        (struct sockaddr*)&connect_to_addr, &connect_to_addrlen)<0) { // 解析目标地址和目标端口
        LogPrintf("tor: Error parsing socket address %s\n", target);
        return false;
    }

    // Create a new socket, set up callbacks and enable notification bits // 创建一个新的套接字，设置回调并设置通知位
    b_conn = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE); // 设置新套接字
    if (!b_conn)
        return false;
    bufferevent_setcb(b_conn, TorControlConnection::readcb, NULL, TorControlConnection::eventcb, this); // 设置回调函数
    bufferevent_enable(b_conn, EV_READ|EV_WRITE);
    this->connected = connected; // 设置连接回调函数
    this->disconnected = disconnected; // 设置断开连接回调函数

    // Finally, connect to target // 最终，连接目标
    if (bufferevent_socket_connect(b_conn, (struct sockaddr*)&connect_to_addr, connect_to_addrlen) < 0) { // 连接套接字地址
        LogPrintf("tor: Error connecting to address %s\n", target);
        return false;
    }
    return true;
}

bool TorControlConnection::Disconnect()
{
    if (b_conn)
        bufferevent_free(b_conn); // 释放连接
    b_conn = 0; // 指针置空，防止出现野指针
    return true;
}

bool TorControlConnection::Command(const std::string &cmd, const ReplyHandlerCB& reply_handler)
{
    if (!b_conn)
        return false;
    struct evbuffer *buf = bufferevent_get_output(b_conn); // 获取输出缓冲区
    if (!buf)
        return false;
    evbuffer_add(buf, cmd.data(), cmd.size()); // 缓冲区追加命令
    evbuffer_add(buf, "\r\n", 2); // 追加 "\r\n"
    reply_handlers.push_back(reply_handler); // 加入响应函数处理队列
    return true;
}

/****** General parsing utilities ********/

/* Split reply line in the form 'AUTH METHODS=...' into a type
 * 'AUTH' and arguments 'METHODS=...'.
 */ // 以格式 'AUTH METHODS=...' 分离响应行到类型 'AUTH' 和参数 'METHODS=...' 中。
static std::pair<std::string,std::string> SplitTorReplyLine(const std::string &s)
{
    size_t ptr=0;
    std::string type;
    while (ptr < s.size() && s[ptr] != ' ') {
        type.push_back(s[ptr]);
        ++ptr;
    }
    if (ptr < s.size())
        ++ptr; // skip ' '
    return make_pair(type, s.substr(ptr));
}

/** Parse reply arguments in the form 'METHODS=COOKIE,SAFECOOKIE COOKIEFILE=".../control_auth_cookie"'.
 */ // 解析反馈参数以这种格式'METHODS=COOKIE,SAFECOOKIE COOKIEFILE=".../control_auth_cookie"'。
static std::map<std::string,std::string> ParseTorReplyMapping(const std::string &s)
{
    std::map<std::string,std::string> mapping;
    size_t ptr=0;
    while (ptr < s.size()) {
        std::string key, value;
        while (ptr < s.size() && s[ptr] != '=') {
            key.push_back(s[ptr]);
            ++ptr;
        }
        if (ptr == s.size()) // unexpected end of line
            return std::map<std::string,std::string>();
        ++ptr; // skip '='
        if (ptr < s.size() && s[ptr] == '"') { // Quoted string
            ++ptr; // skip '='
            bool escape_next = false;
            while (ptr < s.size() && (!escape_next && s[ptr] != '"')) {
                escape_next = (s[ptr] == '\\');
                value.push_back(s[ptr]);
                ++ptr;
            }
            if (ptr == s.size()) // unexpected end of line
                return std::map<std::string,std::string>();
            ++ptr; // skip closing '"'
            /* TODO: unescape value - according to the spec this depends on the
             * context, some strings use C-LogPrintf style escape codes, some
             * don't. So may be better handled at the call site.
             */
        } else { // Unquoted value. Note that values can contain '=' at will, just no spaces
            while (ptr < s.size() && s[ptr] != ' ') {
                value.push_back(s[ptr]);
                ++ptr;
            }
        }
        if (ptr < s.size() && s[ptr] == ' ')
            ++ptr; // skip ' ' after key=value
        mapping[key] = value;
    }
    return mapping;
}

/** Read full contents of a file and return them in a std::string.
 * Returns a pair <status, string>.
 * If an error occured, status will be false, otherwise status will be true and the data will be returned in string.
 *
 * @param maxsize Puts a maximum size limit on the file that is read. If the file is larger than this, truncated data
 *         (with len > maxsize) will be returned.
 */ // 读取某文件的整个内容并以字符串形式返回获取的内容。返回一个对 <状态，读取的字符串>
static std::pair<bool,std::string> ReadBinaryFile(const std::string &filename, size_t maxsize=std::numeric_limits<size_t>::max())
{
    FILE *f = fopen(filename.c_str(), "rb"); // 以 2 进制只读模式打开文件
    if (f == NULL) // 若打开失败
        return std::make_pair(false,""); // 返回<false,空串>对
    std::string retval; // 待获取的字符串类型的文件内容
    char buffer[128]; // 128 字节的缓冲区
    size_t n; // 保存实际读取的字节数
    while ((n=fread(buffer, 1, sizeof(buffer), f)) > 0) { // 读取 128 字节到 buffer，若到文件尾，下次实际读入字节为 0
        retval.append(buffer, buffer+n); // 把实际读取的字节追加到返回值中
        if (retval.size() > maxsize) // 当返回值字符串大小大于最大值时
            break; // 跳出
    }
    fclose(f); // 关闭文件
    return std::make_pair(true,retval); // 返回成功读取的内容<true,文件内容字符串>
}

/** Write contents of std::string to a file.
 * @return true on success.
 */ // 写字符串的内容到某文件。成功返回 true。
static bool WriteBinaryFile(const std::string &filename, const std::string &data)
{
    FILE *f = fopen(filename.c_str(), "wb"); // 以 2 进制只写方式打开文件
    if (f == NULL) // 若文件打开失败
        return false; // 返回 false
    if (fwrite(data.data(), 1, data.size(), f) != data.size()) { // 写入内容
        fclose(f); // 写入失败（写入长度不等于字符串大小），关闭文件
        return false; // 返回 false
    }
    fclose(f); // 成功写入，关闭文件
    return true; // 返回 true
}

/****** Bitcoin specific TorController implementation ********/

/** Controller that connects to Tor control socket, authenticate, then create
 * and maintain a ephemeral hidden service.
 */ // 控制器连接到洋葱路由控制套接字，然后进行身份验证，然后创建并维持一个短暂的隐藏服务。
class TorController
{
public:
    TorController(struct event_base* base, const std::string& target);
    ~TorController();

    /** Get name fo file to store private key in */
    std::string GetPrivateKeyFile(); // 获取（拼接）洋葱路由私钥文件名

    /** Reconnect, after getting disconnected */
    void Reconnect(); // 断开连接后重连
private:
    struct event_base* base; // 事件基对象指针
    std::string target; // 目标
    TorControlConnection conn; // 洋葱路由控制连接对象
    std::string private_key; // 洋葱路由私钥
    std::string service_id;
    bool reconnect; // 再连接标志
    struct event *reconnect_ev; // 再连接事件对象指针
    float reconnect_timeout; // 再连接超时时间
    CService service; // 服务对象（IP+Port）
    /** Cooie for SAFECOOKIE auth */
    std::vector<uint8_t> cookie; // 用于安全 COOKIE 验证的 cookie
    /** ClientNonce for SAFECOOKIE auth */
    std::vector<uint8_t> clientNonce; // 用于安全 COOKIE 验证的客户端随机数

    /** Callback for ADD_ONION result */ // 用于添加洋葱路由连接的回调
    void add_onion_cb(TorControlConnection& conn, const TorControlReply& reply);
    /** Callback for AUTHENTICATE result */ // 用于认证的回调
    void auth_cb(TorControlConnection& conn, const TorControlReply& reply);
    /** Callback for AUTHCHALLENGE result */
    void authchallenge_cb(TorControlConnection& conn, const TorControlReply& reply);
    /** Callback for PROTOCOLINFO result */ // 协议信息结果回调函数
    void protocolinfo_cb(TorControlConnection& conn, const TorControlReply& reply);
    /** Callback after succesful connection */ // 成功连接后的回调函数
    void connected_cb(TorControlConnection& conn);
    /** Callback after connection lost or failed connection attempt */ // 连接断开或失败的连接尝试后的回调函数
    void disconnected_cb(TorControlConnection& conn);

    /** Callback for reconnect timer */ // 用于重连定时器的回调
    static void reconnect_cb(evutil_socket_t fd, short what, void *arg);
};

TorController::TorController(struct event_base* base, const std::string& target):
    base(base), // 初始化事件基对象
    target(target), conn(base), reconnect(true), reconnect_ev(0),
    reconnect_timeout(RECONNECT_TIMEOUT_START) // 设定再连接超时时间
{
    // Start connection attempts immediately // 立刻开始尝试连接
    if (!conn.Connect(target, boost::bind(&TorController::connected_cb, this, _1),
         boost::bind(&TorController::disconnected_cb, this, _1) )) { // 连接洋葱路由控制端口
        LogPrintf("tor: Initiating connection to Tor control port %s failed\n", target);
    }
    // Read service private key if cached // 如果已经缓存，则读取服务私钥
    std::pair<bool,std::string> pkf = ReadBinaryFile(GetPrivateKeyFile()); // 读取洋葱路由私钥文件内容
    if (pkf.first) { // 若读取成功
        LogPrint("tor", "tor: Reading cached private key from %s\n", GetPrivateKeyFile());
        private_key = pkf.second; // 设置私钥
    }
}

TorController::~TorController()
{
    if (reconnect_ev)
        event_del(reconnect_ev);
    if (service.IsValid()) {
        RemoveLocal(service);
    }
}

void TorController::add_onion_cb(TorControlConnection& conn, const TorControlReply& reply)
{
    if (reply.code == 250) {
        LogPrint("tor", "tor: ADD_ONION succesful\n");
        BOOST_FOREACH(const std::string &s, reply.lines) {
            std::map<std::string,std::string> m = ParseTorReplyMapping(s);
            std::map<std::string,std::string>::iterator i;
            if ((i = m.find("ServiceID")) != m.end())
                service_id = i->second;
            if ((i = m.find("PrivateKey")) != m.end())
                private_key = i->second;
        }

        service = CService(service_id+".onion", GetListenPort(), false);
        LogPrintf("tor: Got service ID %s, advertizing service %s\n", service_id, service.ToString());
        if (WriteBinaryFile(GetPrivateKeyFile(), private_key)) {
            LogPrint("tor", "tor: Cached service private key to %s\n", GetPrivateKeyFile());
        } else {
            LogPrintf("tor: Error writing service private key to %s\n", GetPrivateKeyFile());
        }
        AddLocal(service, LOCAL_MANUAL);
        // ... onion requested - keep connection open
    } else if (reply.code == 510) { // 510 Unrecognized command
        LogPrintf("tor: Add onion failed with unrecognized command (You probably need to upgrade Tor)\n");
    } else {
        LogPrintf("tor: Add onion failed; error code %d\n", reply.code);
    }
}

void TorController::auth_cb(TorControlConnection& conn, const TorControlReply& reply)
{
    if (reply.code == 250) {
        LogPrint("tor", "tor: Authentication succesful\n");

        // Now that we know Tor is running setup the proxy for onion addresses
        // if -onion isn't set to something else.
        if (GetArg("-onion", "") == "") {
            proxyType addrOnion = proxyType(CService("127.0.0.1", 9050), true);
            SetProxy(NET_TOR, addrOnion);
            SetReachable(NET_TOR);
        }

        // Finally - now create the service
        if (private_key.empty()) // No private key, generate one
            private_key = "NEW:BEST";
        // Request hidden service, redirect port.
        // Note that the 'virtual' port doesn't have to be the same as our internal port, but this is just a convenient
        // choice.  TODO; refactor the shutdown sequence some day.
        conn.Command(strprintf("ADD_ONION %s Port=%i,127.0.0.1:%i", private_key, GetListenPort(), GetListenPort()),
            boost::bind(&TorController::add_onion_cb, this, _1, _2));
    } else {
        LogPrintf("tor: Authentication failed\n");
    }
}

/** Compute Tor SAFECOOKIE response.
 *
 *    ServerHash is computed as:
 *      HMAC-SHA256("Tor safe cookie authentication server-to-controller hash",
 *                  CookieString | ClientNonce | ServerNonce)
 *    (with the HMAC key as its first argument)
 *
 *    After a controller sends a successful AUTHCHALLENGE command, the
 *    next command sent on the connection must be an AUTHENTICATE command,
 *    and the only authentication string which that AUTHENTICATE command
 *    will accept is:
 *
 *      HMAC-SHA256("Tor safe cookie authentication controller-to-server hash",
 *                  CookieString | ClientNonce | ServerNonce)
 *
 */ // 计算洋葱路由 SAFECOOKIE 响应。
static std::vector<uint8_t> ComputeResponse(const std::string &key, const std::vector<uint8_t> &cookie,  const std::vector<uint8_t> &clientNonce, const std::vector<uint8_t> &serverNonce)
{
    CHMAC_SHA256 computeHash((const uint8_t*)key.data(), key.size());
    std::vector<uint8_t> computedHash(CHMAC_SHA256::OUTPUT_SIZE, 0);
    computeHash.Write(begin_ptr(cookie), cookie.size());
    computeHash.Write(begin_ptr(clientNonce), clientNonce.size());
    computeHash.Write(begin_ptr(serverNonce), serverNonce.size());
    computeHash.Finalize(begin_ptr(computedHash));
    return computedHash;
}

void TorController::authchallenge_cb(TorControlConnection& conn, const TorControlReply& reply)
{
    if (reply.code == 250) {
        LogPrint("tor", "tor: SAFECOOKIE authentication challenge succesful\n");
        std::pair<std::string,std::string> l = SplitTorReplyLine(reply.lines[0]);
        if (l.first == "AUTHCHALLENGE") {
            std::map<std::string,std::string> m = ParseTorReplyMapping(l.second);
            std::vector<uint8_t> serverHash = ParseHex(m["SERVERHASH"]);
            std::vector<uint8_t> serverNonce = ParseHex(m["SERVERNONCE"]);
            LogPrint("tor", "tor: AUTHCHALLENGE ServerHash %s ServerNonce %s\n", HexStr(serverHash), HexStr(serverNonce));
            if (serverNonce.size() != 32) {
                LogPrintf("tor: ServerNonce is not 32 bytes, as required by spec\n");
                return;
            }

            std::vector<uint8_t> computedServerHash = ComputeResponse(TOR_SAFE_SERVERKEY, cookie, clientNonce, serverNonce);
            if (computedServerHash != serverHash) {
                LogPrintf("tor: ServerHash %s does not match expected ServerHash %s\n", HexStr(serverHash), HexStr(computedServerHash));
                return;
            }

            std::vector<uint8_t> computedClientHash = ComputeResponse(TOR_SAFE_CLIENTKEY, cookie, clientNonce, serverNonce);
            conn.Command("AUTHENTICATE " + HexStr(computedClientHash), boost::bind(&TorController::auth_cb, this, _1, _2));
        } else {
            LogPrintf("tor: Invalid reply to AUTHCHALLENGE\n");
        }
    } else {
        LogPrintf("tor: SAFECOOKIE authentication challenge failed\n");
    }
}

void TorController::protocolinfo_cb(TorControlConnection& conn, const TorControlReply& reply)
{
    if (reply.code == 250) {
        std::set<std::string> methods;
        std::string cookiefile;
        /*
         * 250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/home/x/.tor/control_auth_cookie"
         * 250-AUTH METHODS=NULL
         * 250-AUTH METHODS=HASHEDPASSWORD
         */
        BOOST_FOREACH(const std::string &s, reply.lines) {
            std::pair<std::string,std::string> l = SplitTorReplyLine(s);
            if (l.first == "AUTH") {
                std::map<std::string,std::string> m = ParseTorReplyMapping(l.second);
                std::map<std::string,std::string>::iterator i;
                if ((i = m.find("METHODS")) != m.end())
                    boost::split(methods, i->second, boost::is_any_of(","));
                if ((i = m.find("COOKIEFILE")) != m.end())
                    cookiefile = i->second;
            } else if (l.first == "VERSION") {
                std::map<std::string,std::string> m = ParseTorReplyMapping(l.second);
                std::map<std::string,std::string>::iterator i;
                if ((i = m.find("Tor")) != m.end()) {
                    LogPrint("tor", "tor: Connected to Tor version %s\n", i->second);
                }
            }
        }
        BOOST_FOREACH(const std::string &s, methods) {
            LogPrint("tor", "tor: Supported authentication method: %s\n", s);
        }
        // Prefer NULL, otherwise SAFECOOKIE. If a password is provided, use HASHEDPASSWORD
        /* Authentication:
         *   cookie:   hex-encoded ~/.tor/control_auth_cookie
         *   password: "password"
         */
        std::string torpassword = GetArg("-torpassword", "");
        if (methods.count("NULL")) {
            LogPrint("tor", "tor: Using NULL authentication\n");
            conn.Command("AUTHENTICATE", boost::bind(&TorController::auth_cb, this, _1, _2));
        } else if (methods.count("SAFECOOKIE")) {
            // Cookie: hexdump -e '32/1 "%02x""\n"'  ~/.tor/control_auth_cookie
            LogPrint("tor", "tor: Using SAFECOOKIE authentication, reading cookie authentication from %s\n", cookiefile);
            std::pair<bool,std::string> status_cookie = ReadBinaryFile(cookiefile, TOR_COOKIE_SIZE);
            if (status_cookie.first && status_cookie.second.size() == TOR_COOKIE_SIZE) {
                // conn.Command("AUTHENTICATE " + HexStr(status_cookie.second), boost::bind(&TorController::auth_cb, this, _1, _2));
                cookie = std::vector<uint8_t>(status_cookie.second.begin(), status_cookie.second.end());
                clientNonce = std::vector<uint8_t>(TOR_NONCE_SIZE, 0);
                GetRandBytes(&clientNonce[0], TOR_NONCE_SIZE);
                conn.Command("AUTHCHALLENGE SAFECOOKIE " + HexStr(clientNonce), boost::bind(&TorController::authchallenge_cb, this, _1, _2));
            } else {
                if (status_cookie.first) {
                    LogPrintf("tor: Authentication cookie %s is not exactly %i bytes, as is required by the spec\n", cookiefile, TOR_COOKIE_SIZE);
                } else {
                    LogPrintf("tor: Authentication cookie %s could not be opened (check permissions)\n", cookiefile);
                }
            }
        } else if (methods.count("HASHEDPASSWORD")) {
            if (!torpassword.empty()) {
                LogPrint("tor", "tor: Using HASHEDPASSWORD authentication\n");
                boost::replace_all(torpassword, "\"", "\\\"");
                conn.Command("AUTHENTICATE \"" + torpassword + "\"", boost::bind(&TorController::auth_cb, this, _1, _2));
            } else {
                LogPrintf("tor: Password authentication required, but no password provided with -torpassword\n");
            }
        } else {
            LogPrintf("tor: No supported authentication method\n");
        }
    } else {
        LogPrintf("tor: Requesting protocol info failed\n");
    }
}

void TorController::connected_cb(TorControlConnection& conn)
{
    reconnect_timeout = RECONNECT_TIMEOUT_START; // 设置重连超时时间
    // First send a PROTOCOLINFO command to figure out what authentication is expected // 首先发送一条协议信息命令，用于找出预期的身份验证
    if (!conn.Command("PROTOCOLINFO 1", boost::bind(&TorController::protocolinfo_cb, this, _1, _2))) // 发送 "PROTOCOLINFO 1" 命令
        LogPrintf("tor: Error sending initial protocolinfo command\n");
}

void TorController::disconnected_cb(TorControlConnection& conn)
{
    // Stop advertizing service when disconnected // 当断开连接时，停止广告服务
    if (service.IsValid()) // 若服务有效
        RemoveLocal(service); // 移除本地服务
    service = CService(); // 创建服务空对象
    if (!reconnect) // 若重连关闭
        return; // 直接返回

    LogPrint("tor", "tor: Not connected to Tor control port %s, trying to reconnect\n", target);

    // Single-shot timer for reconnect. Use exponential backoff. // 用于重连的单次计时器。使用指数回退
    struct timeval time = MillisToTimeval(int64_t(reconnect_timeout * 1000.0));
    reconnect_ev = event_new(base, -1, 0, reconnect_cb, this); // 创建新的事件对象
    event_add(reconnect_ev, &time); // 添加事件对象和时间间隔
    reconnect_timeout *= RECONNECT_TIMEOUT_EXP;
}

void TorController::Reconnect()
{
    /* Try to reconnect and reestablish if we get booted - for example, Tor
     * may be restarting.
     */ // 若被启动，则尝试重新连接并重新建立连接 - 例如，洋葱路由可能正在重启。
    if (!conn.Connect(target, boost::bind(&TorController::connected_cb, this, _1),
         boost::bind(&TorController::disconnected_cb, this, _1) )) { // 尝试重连
        LogPrintf("tor: Re-initiating connection to Tor control port %s failed\n", target);
    }
}

std::string TorController::GetPrivateKeyFile()
{
    return (GetDataDir() / "onion_private_key").string(); // 返回凭借的数据文件名字符串
}

void TorController::reconnect_cb(evutil_socket_t fd, short what, void *arg)
{
    TorController *self = (TorController*)arg;
    self->Reconnect();
}

/****** Thread ********/
struct event_base *base;
boost::thread torControlThread;

static void TorControlThread()
{
    TorController ctrl(base, GetArg("-torcontrol", DEFAULT_TOR_CONTROL)); // 创建洋葱路由控制器对象

    event_base_dispatch(base);
}

void StartTorControl(boost::thread_group& threadGroup, CScheduler& scheduler)
{
    assert(!base);
#ifdef WIN32
    evthread_use_windows_threads();
#else
    evthread_use_pthreads();
#endif
    base = event_base_new();
    if (!base) {
        LogPrintf("tor: Unable to create event_base\n");
        return;
    }

    torControlThread = boost::thread(boost::bind(&TraceThread<void (*)()>, "torcontrol", &TorControlThread)); // 创建洋葱路由控制线程
}

void InterruptTorControl()
{
    if (base) {
        LogPrintf("tor: Thread interrupt\n");
        event_base_loopbreak(base);
    }
}

void StopTorControl()
{
    if (base) {
        torControlThread.join();
        event_base_free(base);
        base = 0;
    }
}

