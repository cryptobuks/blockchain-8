// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "httpserver.h"

#include "chainparamsbase.h"
#include "compat.h"
#include "util.h"
#include "netbase.h"
#include "rpcprotocol.h" // For HTTP status codes
#include "sync.h"
#include "ui_interface.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
#ifdef _XOPEN_SOURCE_EXTENDED
#include <arpa/inet.h>
#endif
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/foreach.hpp>
#include <boost/scoped_ptr.hpp>

/** Maximum size of http request (request line + headers) */
static const size_t MAX_HEADERS_SIZE = 8192; // http 请求行 + 请求头部大小限制 8K

/** HTTP request work item */ // HTTP 请求工作项目
class HTTPWorkItem : public HTTPClosure
{
public:
    HTTPWorkItem(HTTPRequest* req, const std::string &path, const HTTPRequestHandler& func):
        req(req), path(path), func(func)
    {
    }
    void operator()()
    {
        func(req.get(), path);
    }

    boost::scoped_ptr<HTTPRequest> req;

private:
    std::string path;
    HTTPRequestHandler func;
};

/** Simple work queue for distributing work over multiple threads.
 * Work items are simply callable objects.
 */ // 御用在多个线程上分配工作的简单工作队列。工作项是简易可调用对象。
template <typename WorkItem>
class WorkQueue
{
private:
    /** Mutex protects entire object */ // 互斥锁保护整个对象
    CWaitableCriticalSection cs; // 临界资源
    CConditionVariable cond; // 条件变量
    /* XXX in C++11 we can use std::unique_ptr here and avoid manual cleanup */ // 在 C++11 中我们使用在这里 std::unique_ptr 来避免手动清理
    std::deque<WorkItem*> queue; // 任务队列
    bool running; // 运行状态（决定是否运行/退出循环）
    size_t maxDepth; // 最大深度（容量）
    int numThreads; // 线程数

    /** RAII object to keep track of number of running worker threads */
    class ThreadCounter // 嵌套类，RAII 对象，用于追踪运行的工作线程数
    {
    public:
        WorkQueue &wq; // 外类对象引用
        ThreadCounter(WorkQueue &w): wq(w) // 构造函数
        {
            boost::lock_guard<boost::mutex> lock(wq.cs); // 上锁
            wq.numThreads += 1; // 线程数加 1
        }
        ~ThreadCounter() // 析构函数
        {
            boost::lock_guard<boost::mutex> lock(wq.cs); // 上锁
            wq.numThreads -= 1; // 线程数减 1
            wq.cond.notify_all(); // 通知等待在条件 cond 上的所有线程
        }
    };

public:
    WorkQueue(size_t maxDepth) : running(true),
                                 maxDepth(maxDepth),
                                 numThreads(0)
    {
    }
    /*( Precondition: worker threads have all stopped
     * (call WaitExit)
     */
    ~WorkQueue()
    {
        while (!queue.empty()) {
            delete queue.front();
            queue.pop_front();
        }
    }
    /** Enqueue a work item */
    bool Enqueue(WorkItem* item)
    {
        boost::unique_lock<boost::mutex> lock(cs);
        if (queue.size() >= maxDepth) {
            return false;
        }
        queue.push_back(item);
        cond.notify_one();
        return true;
    }
    /** Thread function */ // 线程函数
    void Run() // 不断从任务队列中读取、删除并执行任务，任务类型为 WorkItem（类类型）
    {
        ThreadCounter count(*this); // 创建线程计数局部对象
        while (running) { // loop
            WorkItem* i = 0;
            {
                boost::unique_lock<boost::mutex> lock(cs);
                while (running && queue.empty()) // 任务队列为空
                    cond.wait(lock); // 等待条件被激活（往队列里添加任务时）
                if (!running)
                    break; // break out of loop
                i = queue.front(); // 取队头元素（任务队列中第一个元素）
                queue.pop_front(); // 队头出队
            }
            (*i)(); // 执行任务
            delete i; // 执行后删除
        }
    }
    /** Interrupt and exit loops */
    void Interrupt() // 打断并退出循环
    {
        boost::unique_lock<boost::mutex> lock(cs);
        running = false; // 改变运行状态为 false
        cond.notify_all();
    }
    /** Wait for worker threads to exit */
    void WaitExit()
    {
        boost::unique_lock<boost::mutex> lock(cs);
        while (numThreads > 0)
            cond.wait(lock);
    }

    /** Return current depth of queue */
    size_t Depth()
    {
        boost::unique_lock<boost::mutex> lock(cs);
        return queue.size();
    }
};

struct HTTPPathHandler
{
    HTTPPathHandler() {}
    HTTPPathHandler(std::string prefix, bool exactMatch, HTTPRequestHandler handler):
        prefix(prefix), exactMatch(exactMatch), handler(handler)
    {
    }
    std::string prefix; // 请求的路径
    bool exactMatch; // 精确匹配 或 前缀匹配（在 http_request_cb 中完成验证）
    HTTPRequestHandler handler; // 对某个 http 路径请求
};

/** HTTP module state */ // HTTP 模块状态

//! libevent event loop // libevent 事件循环
static struct event_base* eventBase = 0;
//! HTTP server // HTTP 服务
struct evhttp* eventHTTP = 0;
//! List of subnets to allow RPC connections from // 允许 RPC 连接进来的子网列表
static std::vector<CSubNet> rpc_allow_subnets; // acl 列表（白名单）
//! Work queue for handling longer requests off the event loop thread
static WorkQueue<HTTPClosure>* workQueue = 0; // 用于处理事件循环线程中较长请求的工作队列
//! Handlers for (sub)paths // 处理函数（子）路径
std::vector<HTTPPathHandler> pathHandlers; // http 请求路径对应的处理函数列表
//! Bound listening sockets // 绑定的用于监听的套接字
std::vector<evhttp_bound_socket *> boundSockets; // 已绑定的 http socket 列表

/** Check if a network address is allowed to access the HTTP server */
static bool ClientAllowed(const CNetAddr& netaddr) // 检查一个网络地址是否被允许访问 HTTP 服务器
{
    if (!netaddr.IsValid()) // 检查地址有效性
        return false;
    BOOST_FOREACH (const CSubNet& subnet, rpc_allow_subnets) // 遍历 ACL 访问控制列表，并与指定地址比对
        if (subnet.Match(netaddr))
            return true;
    return false;
}

/** Initialize ACL list for HTTP server */ // 初始化 HTTP 服务器的 ACL 访问控制列表
static bool InitHTTPAllowList() // ACL: Allow Control List
{
    rpc_allow_subnets.clear(); // 清空子网列表
    rpc_allow_subnets.push_back(CSubNet("127.0.0.0/8")); // always allow IPv4 local subnet // 总是允许 IPv4 本地子网
    rpc_allow_subnets.push_back(CSubNet("::1"));         // always allow IPv6 localhost // 总是允许 IPv6 本地主机
    if (mapMultiArgs.count("-rpcallowip")) { // 若 -rpcallowip 选项设置了
        const std::vector<std::string>& vAllow = mapMultiArgs["-rpcallowip"]; // 获取该 acl 列表
        BOOST_FOREACH (std::string strAllow, vAllow) { // 遍历该列表
            CSubNet subnet(strAllow); // 创建子网对象
            if (!subnet.IsValid()) { // 检查子网有效性
                uiInterface.ThreadSafeMessageBox(
                    strprintf("Invalid -rpcallowip subnet specification: %s. Valid are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24).", strAllow),
                    "", CClientUIInterface::MSG_ERROR);
                return false;
            }
            rpc_allow_subnets.push_back(subnet); // 加入 ACL 列表
        }
    }
    std::string strAllowed; // 记录日志
    BOOST_FOREACH (const CSubNet& subnet, rpc_allow_subnets) // 遍历 acl 列表
        strAllowed += subnet.ToString() + " "; // 拼接
    LogPrint("http", "Allowing HTTP connections from: %s\n", strAllowed); // 记录白名单
    return true; // 成功返回 true
}

/** HTTP request method as string - use for logging only */
static std::string RequestMethodString(HTTPRequest::RequestMethod m)
{
    switch (m) {
    case HTTPRequest::GET:
        return "GET";
        break;
    case HTTPRequest::POST:
        return "POST";
        break;
    case HTTPRequest::HEAD:
        return "HEAD";
        break;
    case HTTPRequest::PUT:
        return "PUT";
        break;
    default:
        return "unknown";
    }
}

/** HTTP request callback */ // HTTP 请求回调函数
static void http_request_cb(struct evhttp_request* req, void* arg)
{
    std::auto_ptr<HTTPRequest> hreq(new HTTPRequest(req)); // 根据 HTTP 请求创建一个 HTTPRequest 对象

    LogPrint("http", "Received a %s request for %s from %s\n",
             RequestMethodString(hreq->GetRequestMethod()), hreq->GetURI(), hreq->GetPeer().ToString());

    // Early address-based allow check // 检查请求连入地址是否被允许
    if (!ClientAllowed(hreq->GetPeer())) { // 即该请求的源地址是否存在于 ACL 访问控制列表中
        hreq->WriteReply(HTTP_FORBIDDEN);
        return;
    }

    // Early reject unknown HTTP methods // 提前拒绝未知的 HTTP 方法
    if (hreq->GetRequestMethod() == HTTPRequest::UNKNOWN) { // 若请求方法未知
        hreq->WriteReply(HTTP_BADMETHOD); // 响应错误方法
        return; // 直接退出
    }

    // Find registered handler for prefix // 通过前缀查找注册的处理函数
    std::string strURI = hreq->GetURI(); // 获取 URI（Uniform Resource Identifier，统一资源标识符，包含 URL）
    std::string path; // 处理函数对应的路径
    std::vector<HTTPPathHandler>::const_iterator i = pathHandlers.begin();
    std::vector<HTTPPathHandler>::const_iterator iend = pathHandlers.end();
    for (; i != iend; ++i) { // 遍历处理函数
        bool match = false; // 匹配标志，初始化为 false
        if (i->exactMatch) // 若为精确匹配
            match = (strURI == i->prefix); // 检查是否匹配
        else // 否则，为前缀匹配
            match = (strURI.substr(0, i->prefix.size()) == i->prefix); // 比较前缀是否匹配
        if (match) { // 若匹配
            path = strURI.substr(i->prefix.size()); // 获取相应路径
            break; // 跳出
        }
    } // 否则，继续 loop

    // Dispatch to worker thread // 派发到工作线程
    if (i != iend) { // 若找到了对应的处理函数，则派发到工作线程
        std::auto_ptr<HTTPWorkItem> item(new HTTPWorkItem(hreq.release(), path, i->handler)); // 把请求，请求的路径和对应的处理函数封装为 HTTPWorkItem 对象
        assert(workQueue);
        if (workQueue->Enqueue(item.get())) // 把该工作对象加入任务队列，该任务队列由工作线程不断处理
            item.release(); /* if true, queue took ownership */ // 如果为 true，队列获得所有权
        else
            item->req->WriteReply(HTTP_INTERNAL, "Work queue depth exceeded");
    } else { // 否则，响应未找到相应函数
        hreq->WriteReply(HTTP_NOTFOUND);
    }
}

/** Callback to reject HTTP requests after shutdown. */ // 在关闭后用于拒绝 HTTP 请求的回调函数
static void http_reject_request_cb(struct evhttp_request* req, void*)
{
    LogPrint("http", "Rejecting request while shutting down\n");
    evhttp_send_error(req, HTTP_SERVUNAVAIL, NULL);
}

/** Event dispatcher thread */ // 事件派发线程
static void ThreadHTTP(struct event_base* base, struct evhttp* http)
{
    RenameThread("bitcoin-http"); // 重命名线程
    LogPrint("http", "Entering http event loop\n");
    event_base_dispatch(base); // 进入 http 事件循环
    // Event loop will be interrupted by InterruptHTTPServer() // 事件循环将被 InterruptHTTPServer() 打断
    LogPrint("http", "Exited http event loop\n");
}

/** Bind HTTP server to specified addresses */ // 绑定 HTTP 服务器到指定地址
static bool HTTPBindAddresses(struct evhttp* http)
{
    int defaultPort = GetArg("-rpcport", BaseParams().RPCPort()); // 设置 RPC 端口
    std::vector<std::pair<std::string, uint16_t> > endpoints; // std::pair<IP, PORT>

    // Determine what addresses to bind to // 确定要绑定的地址集
    if (!mapArgs.count("-rpcallowip")) { // Default to loopback if not allowing external IPs // 若不允许外部 IP，则默认为环回地址
        endpoints.push_back(std::make_pair("::1", defaultPort));
        endpoints.push_back(std::make_pair("127.0.0.1", defaultPort));
        if (mapArgs.count("-rpcbind")) { // 若 -rpcallowip 为设置时，-rpcbind 无效
            LogPrintf("WARNING: option -rpcbind was ignored because -rpcallowip was not specified, refusing to allow everyone to connect\n");
        }
    } else if (mapArgs.count("-rpcbind")) { // Specific bind address // 指定的绑定地址
        const std::vector<std::string>& vbind = mapMultiArgs["-rpcbind"]; // 获取绑定地址列表
        for (std::vector<std::string>::const_iterator i = vbind.begin(); i != vbind.end(); ++i) { // 遍历该列表
            int port = defaultPort; // 获取端口号
            std::string host;
            SplitHostPort(*i, port, host); // 分离主机和端口
            endpoints.push_back(std::make_pair(host, port)); // 加入端点列表
        }
    } else { // No specific bind address specified, bind to any // 未指定绑定地址，则绑定任意
        endpoints.push_back(std::make_pair("::", defaultPort));
        endpoints.push_back(std::make_pair("0.0.0.0", defaultPort));
    }

    // Bind addresses // 绑定地址集
    for (std::vector<std::pair<std::string, uint16_t> >::iterator i = endpoints.begin(); i != endpoints.end(); ++i) { // 遍历端点列表
        LogPrint("http", "Binding RPC on address %s port %i\n", i->first, i->second);
        evhttp_bound_socket *bind_handle = evhttp_bind_socket_with_handle(http, i->first.empty() ? NULL : i->first.c_str(), i->second); // 绑定地址和端口
        if (bind_handle) { // 若绑定成功
            boundSockets.push_back(bind_handle); // 加入已绑定的 http socket 列表
        } else {
            LogPrintf("Binding RPC on address %s port %i failed.\n", i->first, i->second);
        }
    }
    return !boundSockets.empty(); // 若绑定成功，返回 true
}

/** Simple wrapper to set thread name and run work queue */ // 设置线程名并运行工作队列的简单包装器
static void HTTPWorkQueueRun(WorkQueue<HTTPClosure>* queue)
{
    RenameThread("bitcoin-httpworker"); // 重命名线程
    queue->Run(); // 依次运行队列中的任务
}

/** libevent event log callback */ // libevent 事件日志回调函数
static void libevent_log_cb(int severity, const char *msg)
{
#ifndef EVENT_LOG_WARN // EVENT_LOG_WARN 在 2.0.19 中添加；但在 _EVENT_LOG_WARN 已存在。
// EVENT_LOG_WARN was added in 2.0.19; but before then _EVENT_LOG_WARN existed.
# define EVENT_LOG_WARN _EVENT_LOG_WARN
#endif
    if (severity >= EVENT_LOG_WARN) // Log warn messages and higher without debug category
        LogPrintf("libevent: %s\n", msg); // 记录警告信息和更高的没有调试类别的信息
    else
        LogPrint("libevent", "libevent: %s\n", msg);
}

bool InitHTTPServer()
{
    struct evhttp* http = 0;
    struct event_base* base = 0;

    if (!InitHTTPAllowList()) // 1.初始化 HTTP ACL 访问控制列表（白名单）
        return false;

    if (GetBoolArg("-rpcssl", false)) { // rpcssl 默认关闭，当前版本不支持，如果设置了就报错
        uiInterface.ThreadSafeMessageBox(
            "SSL mode for RPC (-rpcssl) is no longer supported.",
            "", CClientUIInterface::MSG_ERROR);
        return false;
    }

    // Redirect libevent's logging to our own log // 2.重定向 libevent 的日志到当前日志系统
    event_set_log_callback(&libevent_log_cb); // 设置 libevent 日志回调函数
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
    // If -debug=libevent, set full libevent debugging. // 如果 -debug=libevent，设置完整的 libevent 调试信息。
    // Otherwise, disable all libevent debugging. // 否则，禁止全部 libevent 调试信息。
    if (LogAcceptCategory("libevent")) // 根据调试选项设置调试日志记录内容
        event_enable_debug_logging(EVENT_DBG_ALL);
    else
        event_enable_debug_logging(EVENT_DBG_NONE);
#endif
#ifdef WIN32 // 3.初始化 libevent 的 evhttp 服务端
    evthread_use_windows_threads();
#else
    evthread_use_pthreads(); // 3.1.初始化 libevent 多线程支持
#endif

    base = event_base_new(); // XXX RAII // 3.2.创建 event_base 对象
    if (!base) {
        LogPrintf("Couldn't create an event_base: exiting\n");
        return false;
    }

    /* Create a new evhttp object to handle requests. */ // 3.3.创建一个新的 evhttp 对象来处理请求。
    http = evhttp_new(base); // XXX RAII 利用 event_base 创建 evhttp 对象
    if (!http) {
        LogPrintf("couldn't create evhttp. Exiting.\n");
        event_base_free(base);
        return false;
    }

    evhttp_set_timeout(http, GetArg("-rpcservertimeout", DEFAULT_HTTP_SERVER_TIMEOUT)); // 3.4.设置 http 服务超时时间为 rpc 服务超时，默认 30 秒
    evhttp_set_max_headers_size(http, MAX_HEADERS_SIZE); // http 头大小，默认 8K
    evhttp_set_max_body_size(http, MAX_SIZE); // 设置消息体大小，默认 32M
    evhttp_set_gencb(http, http_request_cb, NULL); // 3.5.设置处理请求的回调函数 http_request_cb

    if (!HTTPBindAddresses(http)) { // 3.6.evhttp_bind_socket(http, "0.0.0.0", port),绑定服务地址和端口
        LogPrintf("Unable to bind any endpoint for RPC server\n");
        evhttp_free(http);
        event_base_free(base);
        return false;
    }

    LogPrint("http", "Initialized HTTP server\n"); // evhttp 服务器端初始化完成
    int workQueueDepth = std::max((long)GetArg("-rpcworkqueue", DEFAULT_HTTP_WORKQUEUE), 1L); // 获取 HTTP 任务队列最大容量，默认 16，最小为 1
    LogPrintf("HTTP: creating work queue of depth %d\n", workQueueDepth);

    workQueue = new WorkQueue<HTTPClosure>(workQueueDepth); // 4.创建任务队列
    eventBase = base;
    eventHTTP = http;
    return true; // 成功返回 true
}

boost::thread threadHTTP;

bool StartHTTPServer()
{
    LogPrint("http", "Starting HTTP server\n");
    int rpcThreads = std::max((long)GetArg("-rpcthreads", DEFAULT_HTTP_THREADS), 1L); // 1.获取 RPC 线程数，默认为 4，至少为 1
    LogPrintf("HTTP: starting %d worker threads\n", rpcThreads);
    threadHTTP = boost::thread(boost::bind(&ThreadHTTP, eventBase, eventHTTP)); // 2.派发事件循环，http 协议启动

    for (int i = 0; i < rpcThreads; i++) // 3.创建 HTTP 工作队列处理线程
        boost::thread(boost::bind(&HTTPWorkQueueRun, workQueue));
    return true;
}

void InterruptHTTPServer()
{
    LogPrint("http", "Interrupting HTTP server\n");
    if (eventHTTP) {
        // Unlisten sockets
        BOOST_FOREACH (evhttp_bound_socket *socket, boundSockets) {
            evhttp_del_accept_socket(eventHTTP, socket);
        }
        // Reject requests on current connections
        evhttp_set_gencb(eventHTTP, http_reject_request_cb, NULL);
    }
    if (workQueue)
        workQueue->Interrupt();
}

void StopHTTPServer()
{
    LogPrint("http", "Stopping HTTP server\n");
    if (workQueue) {
        LogPrint("http", "Waiting for HTTP worker threads to exit\n");
        workQueue->WaitExit();
        delete workQueue;
    }
    if (eventBase) {
        LogPrint("http", "Waiting for HTTP event thread to exit\n");
        // Give event loop a few seconds to exit (to send back last RPC responses), then break it
        // Before this was solved with event_base_loopexit, but that didn't work as expected in
        // at least libevent 2.0.21 and always introduced a delay. In libevent
        // master that appears to be solved, so in the future that solution
        // could be used again (if desirable).
        // (see discussion in https://github.com/bitcoin/bitcoin/pull/6990)
#if BOOST_VERSION >= 105000
        if (!threadHTTP.try_join_for(boost::chrono::milliseconds(2000))) {
#else
        if (!threadHTTP.timed_join(boost::posix_time::milliseconds(2000))) {
#endif
            LogPrintf("HTTP event loop did not exit within allotted time, sending loopbreak\n");
            event_base_loopbreak(eventBase);
            threadHTTP.join();
        }
    }
    if (eventHTTP) {
        evhttp_free(eventHTTP);
        eventHTTP = 0;
    }
    if (eventBase) {
        event_base_free(eventBase);
        eventBase = 0;
    }
    LogPrint("http", "Stopped HTTP server\n");
}

struct event_base* EventBase()
{
    return eventBase;
}

static void httpevent_callback_fn(evutil_socket_t, short, void* data)
{
    // Static handler: simply call inner handler
    HTTPEvent *self = ((HTTPEvent*)data);
    self->handler();
    if (self->deleteWhenTriggered)
        delete self;
}

HTTPEvent::HTTPEvent(struct event_base* base, bool deleteWhenTriggered, const boost::function<void(void)>& handler):
    deleteWhenTriggered(deleteWhenTriggered), handler(handler)
{
    ev = event_new(base, -1, 0, httpevent_callback_fn, this);
    assert(ev);
}
HTTPEvent::~HTTPEvent()
{
    event_free(ev);
}
void HTTPEvent::trigger(struct timeval* tv)
{
    if (tv == NULL)
        event_active(ev, 0, 0); // immediately trigger event in main thread // 立刻在主线程中触发事件
    else
        evtimer_add(ev, tv); // trigger after timeval passed // 在过去 timeval 秒后触发
}
HTTPRequest::HTTPRequest(struct evhttp_request* req) : req(req),
                                                       replySent(false)
{
}
HTTPRequest::~HTTPRequest()
{
    if (!replySent) {
        // Keep track of whether reply was sent to avoid request leaks
        LogPrintf("%s: Unhandled request\n", __func__);
        WriteReply(HTTP_INTERNAL, "Unhandled request");
    }
    // evhttpd cleans up the request, as long as a reply was sent.
}

std::pair<bool, std::string> HTTPRequest::GetHeader(const std::string& hdr)
{
    const struct evkeyvalq* headers = evhttp_request_get_input_headers(req); // 获取请求头部
    assert(headers);
    const char* val = evhttp_find_header(headers, hdr.c_str()); // 获取头部指定键的值
    if (val) // 若该值存在
        return std::make_pair(true, val); // 配对返回
    else
        return std::make_pair(false, "");
}

std::string HTTPRequest::ReadBody()
{
    struct evbuffer* buf = evhttp_request_get_input_buffer(req); // 获取请求的输入缓冲区
    if (!buf)
        return "";
    size_t size = evbuffer_get_length(buf); // 获取缓冲区大小
    /** Trivial implementation: if this is ever a performance bottleneck,
     * internal copying can be avoided in multi-segment buffers by using
     * evbuffer_peek and an awkward loop. Though in that case, it'd be even
     * better to not copy into an intermediate string but use a stream
     * abstraction to consume the evbuffer on the fly in the parsing algorithm.
     */ // 简单的实现：如果这是一个性能瓶颈，通过使用 evbuffer_peek 和笨拙的循环可以在多端缓冲区中避免内部复制。
    const char* data = (const char*)evbuffer_pullup(buf, size); // 获取指定大小的内容
    if (!data) // returns NULL in case of empty buffer // 若为空缓冲区
        return ""; // 返回 ""
    std::string rv(data, size); // 创建一个字符串对象
    evbuffer_drain(buf, size); // 把这部分获取的数据从缓冲区前面移除
    return rv; // 返回缓冲区内容
}

void HTTPRequest::WriteHeader(const std::string& hdr, const std::string& value)
{
    struct evkeyvalq* headers = evhttp_request_get_output_headers(req); // 获取请求头部指针
    assert(headers);
    evhttp_add_header(headers, hdr.c_str(), value.c_str()); // 把相关信息添加到请求头部
}

/** Closure sent to main thread to request a reply to be sent to
 * a HTTP request.
 * Replies must be sent in the main loop in the main http thread,
 * this cannot be done from worker threads.
 */ // 发送到主线程来请求响应用于发送一个 HTTP 请求。反馈必须在主 http 线程的主循环中发送，而不能从工作线程中发送。
void HTTPRequest::WriteReply(int nStatus, const std::string& strReply)
{
    assert(!replySent && req); // 响应未发送 且 存在 http 请求
    // Send event to main http thread to send reply message // 发送事件到主 http 线程来发送响应信息
    struct evbuffer* evb = evhttp_request_get_output_buffer(req); // 获取输出缓冲区结构体指针
    assert(evb);
    evbuffer_add(evb, strReply.data(), strReply.size()); // 添加响应数据和大小到输出缓冲区
    HTTPEvent* ev = new HTTPEvent(eventBase, true, // 构造一个 HTTP 事件对象
        boost::bind(evhttp_send_reply, req, nStatus, (const char*)NULL, (struct evbuffer *)NULL));
    ev->trigger(0); // 立刻触发该事件
    replySent = true; // 响应发送标志置为 true
    req = 0; // transferred back to main thread // 切换回主线程
}

CService HTTPRequest::GetPeer()
{
    evhttp_connection* con = evhttp_request_get_connection(req);
    CService peer;
    if (con) {
        // evhttp retains ownership over returned address string
        const char* address = "";
        uint16_t port = 0;
        evhttp_connection_get_peer(con, (char**)&address, &port); // 从 HTTP 连接中获取对方 IP 和 PORT
        peer = CService(address, port);
    }
    return peer;
}

std::string HTTPRequest::GetURI()
{
    return evhttp_request_get_uri(req);
}

HTTPRequest::RequestMethod HTTPRequest::GetRequestMethod()
{
    switch (evhttp_request_get_command(req)) { // 获取请求命令（方式）
    case EVHTTP_REQ_GET: // 返回相应的方式
        return GET;
        break;
    case EVHTTP_REQ_POST:
        return POST;
        break;
    case EVHTTP_REQ_HEAD:
        return HEAD;
        break;
    case EVHTTP_REQ_PUT:
        return PUT;
        break;
    default:
        return UNKNOWN;
        break;
    }
}

void RegisterHTTPHandler(const std::string &prefix, bool exactMatch, const HTTPRequestHandler &handler)
{
    LogPrint("http", "Registering HTTP handler for %s (exactmatch %d)\n", prefix, exactMatch);
    pathHandlers.push_back(HTTPPathHandler(prefix, exactMatch, handler)); // 加入处理函数列表
}

void UnregisterHTTPHandler(const std::string &prefix, bool exactMatch)
{
    std::vector<HTTPPathHandler>::iterator i = pathHandlers.begin();
    std::vector<HTTPPathHandler>::iterator iend = pathHandlers.end();
    for (; i != iend; ++i)
        if (i->prefix == prefix && i->exactMatch == exactMatch)
            break;
    if (i != iend)
    {
        LogPrint("http", "Unregistering HTTP handler for %s (exactmatch %d)\n", prefix, exactMatch);
        pathHandlers.erase(i);
    }
}

