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
static const size_t MAX_HEADERS_SIZE = 8192; // http ������ + ����ͷ����С���� 8K

/** HTTP request work item */ // HTTP ��������Ŀ
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
 */ // �����ڶ���߳��Ϸ��乤���ļ򵥹������С��������Ǽ��׿ɵ��ö���
template <typename WorkItem>
class WorkQueue
{
private:
    /** Mutex protects entire object */ // ������������������
    CWaitableCriticalSection cs; // �ٽ���Դ
    CConditionVariable cond; // ��������
    /* XXX in C++11 we can use std::unique_ptr here and avoid manual cleanup */ // �� C++11 ������ʹ�������� std::unique_ptr �������ֶ�����
    std::deque<WorkItem*> queue; // �������
    bool running; // ����״̬�������Ƿ�����/�˳�ѭ����
    size_t maxDepth; // �����ȣ�������
    int numThreads; // �߳���

    /** RAII object to keep track of number of running worker threads */
    class ThreadCounter // Ƕ���࣬RAII ��������׷�����еĹ����߳���
    {
    public:
        WorkQueue &wq; // �����������
        ThreadCounter(WorkQueue &w): wq(w) // ���캯��
        {
            boost::lock_guard<boost::mutex> lock(wq.cs); // ����
            wq.numThreads += 1; // �߳����� 1
        }
        ~ThreadCounter() // ��������
        {
            boost::lock_guard<boost::mutex> lock(wq.cs); // ����
            wq.numThreads -= 1; // �߳����� 1
            wq.cond.notify_all(); // ֪ͨ�ȴ������� cond �ϵ������߳�
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
    /** Thread function */ // �̺߳���
    void Run() // ���ϴ���������ж�ȡ��ɾ����ִ��������������Ϊ WorkItem�������ͣ�
    {
        ThreadCounter count(*this); // �����̼߳����ֲ�����
        while (running) { // loop
            WorkItem* i = 0;
            {
                boost::unique_lock<boost::mutex> lock(cs);
                while (running && queue.empty()) // �������Ϊ��
                    cond.wait(lock); // �ȴ�������������������������ʱ��
                if (!running)
                    break; // break out of loop
                i = queue.front(); // ȡ��ͷԪ�أ���������е�һ��Ԫ�أ�
                queue.pop_front(); // ��ͷ����
            }
            (*i)(); // ִ������
            delete i; // ִ�к�ɾ��
        }
    }
    /** Interrupt and exit loops */
    void Interrupt() // ��ϲ��˳�ѭ��
    {
        boost::unique_lock<boost::mutex> lock(cs);
        running = false; // �ı�����״̬Ϊ false
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
    std::string prefix; // �����·��
    bool exactMatch; // ��ȷƥ�� �� ǰ׺ƥ�䣨�� http_request_cb �������֤��
    HTTPRequestHandler handler; // ��ĳ�� http ·������
};

/** HTTP module state */ // HTTP ģ��״̬

//! libevent event loop // libevent �¼�ѭ��
static struct event_base* eventBase = 0;
//! HTTP server // HTTP ����
struct evhttp* eventHTTP = 0;
//! List of subnets to allow RPC connections from // ���� RPC ���ӽ����������б�
static std::vector<CSubNet> rpc_allow_subnets; // acl �б���������
//! Work queue for handling longer requests off the event loop thread
static WorkQueue<HTTPClosure>* workQueue = 0; // ���ڴ����¼�ѭ���߳��нϳ�����Ĺ�������
//! Handlers for (sub)paths // ���������ӣ�·��
std::vector<HTTPPathHandler> pathHandlers; // http ����·����Ӧ�Ĵ������б�
//! Bound listening sockets // �󶨵����ڼ������׽���
std::vector<evhttp_bound_socket *> boundSockets; // �Ѱ󶨵� http socket �б�

/** Check if a network address is allowed to access the HTTP server */
static bool ClientAllowed(const CNetAddr& netaddr) // ���һ�������ַ�Ƿ�������� HTTP ������
{
    if (!netaddr.IsValid()) // ����ַ��Ч��
        return false;
    BOOST_FOREACH (const CSubNet& subnet, rpc_allow_subnets) // ���� ACL ���ʿ����б�����ָ����ַ�ȶ�
        if (subnet.Match(netaddr))
            return true;
    return false;
}

/** Initialize ACL list for HTTP server */ // ��ʼ�� HTTP �������� ACL ���ʿ����б�
static bool InitHTTPAllowList() // ACL: Allow Control List
{
    rpc_allow_subnets.clear(); // ��������б�
    rpc_allow_subnets.push_back(CSubNet("127.0.0.0/8")); // always allow IPv4 local subnet // �������� IPv4 ��������
    rpc_allow_subnets.push_back(CSubNet("::1"));         // always allow IPv6 localhost // �������� IPv6 ��������
    if (mapMultiArgs.count("-rpcallowip")) { // �� -rpcallowip ѡ��������
        const std::vector<std::string>& vAllow = mapMultiArgs["-rpcallowip"]; // ��ȡ�� acl �б�
        BOOST_FOREACH (std::string strAllow, vAllow) { // �������б�
            CSubNet subnet(strAllow); // ������������
            if (!subnet.IsValid()) { // ���������Ч��
                uiInterface.ThreadSafeMessageBox(
                    strprintf("Invalid -rpcallowip subnet specification: %s. Valid are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24).", strAllow),
                    "", CClientUIInterface::MSG_ERROR);
                return false;
            }
            rpc_allow_subnets.push_back(subnet); // ���� ACL �б�
        }
    }
    std::string strAllowed; // ��¼��־
    BOOST_FOREACH (const CSubNet& subnet, rpc_allow_subnets) // ���� acl �б�
        strAllowed += subnet.ToString() + " "; // ƴ��
    LogPrint("http", "Allowing HTTP connections from: %s\n", strAllowed); // ��¼������
    return true; // �ɹ����� true
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

/** HTTP request callback */ // HTTP ����ص�����
static void http_request_cb(struct evhttp_request* req, void* arg)
{
    std::auto_ptr<HTTPRequest> hreq(new HTTPRequest(req)); // ���� HTTP ���󴴽�һ�� HTTPRequest ����

    LogPrint("http", "Received a %s request for %s from %s\n",
             RequestMethodString(hreq->GetRequestMethod()), hreq->GetURI(), hreq->GetPeer().ToString());

    // Early address-based allow check // ������������ַ�Ƿ�����
    if (!ClientAllowed(hreq->GetPeer())) { // ���������Դ��ַ�Ƿ������ ACL ���ʿ����б���
        hreq->WriteReply(HTTP_FORBIDDEN);
        return;
    }

    // Early reject unknown HTTP methods // ��ǰ�ܾ�δ֪�� HTTP ����
    if (hreq->GetRequestMethod() == HTTPRequest::UNKNOWN) { // �����󷽷�δ֪
        hreq->WriteReply(HTTP_BADMETHOD); // ��Ӧ���󷽷�
        return; // ֱ���˳�
    }

    // Find registered handler for prefix // ͨ��ǰ׺����ע��Ĵ�����
    std::string strURI = hreq->GetURI(); // ��ȡ URI��Uniform Resource Identifier��ͳһ��Դ��ʶ�������� URL��
    std::string path; // ��������Ӧ��·��
    std::vector<HTTPPathHandler>::const_iterator i = pathHandlers.begin();
    std::vector<HTTPPathHandler>::const_iterator iend = pathHandlers.end();
    for (; i != iend; ++i) { // ����������
        bool match = false; // ƥ���־����ʼ��Ϊ false
        if (i->exactMatch) // ��Ϊ��ȷƥ��
            match = (strURI == i->prefix); // ����Ƿ�ƥ��
        else // ����Ϊǰ׺ƥ��
            match = (strURI.substr(0, i->prefix.size()) == i->prefix); // �Ƚ�ǰ׺�Ƿ�ƥ��
        if (match) { // ��ƥ��
            path = strURI.substr(i->prefix.size()); // ��ȡ��Ӧ·��
            break; // ����
        }
    } // ���򣬼��� loop

    // Dispatch to worker thread // �ɷ��������߳�
    if (i != iend) { // ���ҵ��˶�Ӧ�Ĵ����������ɷ��������߳�
        std::auto_ptr<HTTPWorkItem> item(new HTTPWorkItem(hreq.release(), path, i->handler)); // �����������·���Ͷ�Ӧ�Ĵ�������װΪ HTTPWorkItem ����
        assert(workQueue);
        if (workQueue->Enqueue(item.get())) // �Ѹù����������������У�����������ɹ����̲߳��ϴ���
            item.release(); /* if true, queue took ownership */ // ���Ϊ true�����л������Ȩ
        else
            item->req->WriteReply(HTTP_INTERNAL, "Work queue depth exceeded");
    } else { // ������Ӧδ�ҵ���Ӧ����
        hreq->WriteReply(HTTP_NOTFOUND);
    }
}

/** Callback to reject HTTP requests after shutdown. */ // �ڹرպ����ھܾ� HTTP ����Ļص�����
static void http_reject_request_cb(struct evhttp_request* req, void*)
{
    LogPrint("http", "Rejecting request while shutting down\n");
    evhttp_send_error(req, HTTP_SERVUNAVAIL, NULL);
}

/** Event dispatcher thread */ // �¼��ɷ��߳�
static void ThreadHTTP(struct event_base* base, struct evhttp* http)
{
    RenameThread("bitcoin-http"); // �������߳�
    LogPrint("http", "Entering http event loop\n");
    event_base_dispatch(base); // ���� http �¼�ѭ��
    // Event loop will be interrupted by InterruptHTTPServer() // �¼�ѭ������ InterruptHTTPServer() ���
    LogPrint("http", "Exited http event loop\n");
}

/** Bind HTTP server to specified addresses */ // �� HTTP ��������ָ����ַ
static bool HTTPBindAddresses(struct evhttp* http)
{
    int defaultPort = GetArg("-rpcport", BaseParams().RPCPort()); // ���� RPC �˿�
    std::vector<std::pair<std::string, uint16_t> > endpoints; // std::pair<IP, PORT>

    // Determine what addresses to bind to // ȷ��Ҫ�󶨵ĵ�ַ��
    if (!mapArgs.count("-rpcallowip")) { // Default to loopback if not allowing external IPs // ���������ⲿ IP����Ĭ��Ϊ���ص�ַ
        endpoints.push_back(std::make_pair("::1", defaultPort));
        endpoints.push_back(std::make_pair("127.0.0.1", defaultPort));
        if (mapArgs.count("-rpcbind")) { // �� -rpcallowip Ϊ����ʱ��-rpcbind ��Ч
            LogPrintf("WARNING: option -rpcbind was ignored because -rpcallowip was not specified, refusing to allow everyone to connect\n");
        }
    } else if (mapArgs.count("-rpcbind")) { // Specific bind address // ָ���İ󶨵�ַ
        const std::vector<std::string>& vbind = mapMultiArgs["-rpcbind"]; // ��ȡ�󶨵�ַ�б�
        for (std::vector<std::string>::const_iterator i = vbind.begin(); i != vbind.end(); ++i) { // �������б�
            int port = defaultPort; // ��ȡ�˿ں�
            std::string host;
            SplitHostPort(*i, port, host); // ���������Ͷ˿�
            endpoints.push_back(std::make_pair(host, port)); // ����˵��б�
        }
    } else { // No specific bind address specified, bind to any // δָ���󶨵�ַ���������
        endpoints.push_back(std::make_pair("::", defaultPort));
        endpoints.push_back(std::make_pair("0.0.0.0", defaultPort));
    }

    // Bind addresses // �󶨵�ַ��
    for (std::vector<std::pair<std::string, uint16_t> >::iterator i = endpoints.begin(); i != endpoints.end(); ++i) { // �����˵��б�
        LogPrint("http", "Binding RPC on address %s port %i\n", i->first, i->second);
        evhttp_bound_socket *bind_handle = evhttp_bind_socket_with_handle(http, i->first.empty() ? NULL : i->first.c_str(), i->second); // �󶨵�ַ�Ͷ˿�
        if (bind_handle) { // ���󶨳ɹ�
            boundSockets.push_back(bind_handle); // �����Ѱ󶨵� http socket �б�
        } else {
            LogPrintf("Binding RPC on address %s port %i failed.\n", i->first, i->second);
        }
    }
    return !boundSockets.empty(); // ���󶨳ɹ������� true
}

/** Simple wrapper to set thread name and run work queue */ // �����߳��������й������еļ򵥰�װ��
static void HTTPWorkQueueRun(WorkQueue<HTTPClosure>* queue)
{
    RenameThread("bitcoin-httpworker"); // �������߳�
    queue->Run(); // �������ж����е�����
}

/** libevent event log callback */ // libevent �¼���־�ص�����
static void libevent_log_cb(int severity, const char *msg)
{
#ifndef EVENT_LOG_WARN // EVENT_LOG_WARN �� 2.0.19 ����ӣ����� _EVENT_LOG_WARN �Ѵ��ڡ�
// EVENT_LOG_WARN was added in 2.0.19; but before then _EVENT_LOG_WARN existed.
# define EVENT_LOG_WARN _EVENT_LOG_WARN
#endif
    if (severity >= EVENT_LOG_WARN) // Log warn messages and higher without debug category
        LogPrintf("libevent: %s\n", msg); // ��¼������Ϣ�͸��ߵ�û�е���������Ϣ
    else
        LogPrint("libevent", "libevent: %s\n", msg);
}

bool InitHTTPServer()
{
    struct evhttp* http = 0;
    struct event_base* base = 0;

    if (!InitHTTPAllowList()) // 1.��ʼ�� HTTP ACL ���ʿ����б���������
        return false;

    if (GetBoolArg("-rpcssl", false)) { // rpcssl Ĭ�Ϲرգ���ǰ�汾��֧�֣���������˾ͱ���
        uiInterface.ThreadSafeMessageBox(
            "SSL mode for RPC (-rpcssl) is no longer supported.",
            "", CClientUIInterface::MSG_ERROR);
        return false;
    }

    // Redirect libevent's logging to our own log // 2.�ض��� libevent ����־����ǰ��־ϵͳ
    event_set_log_callback(&libevent_log_cb); // ���� libevent ��־�ص�����
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
    // If -debug=libevent, set full libevent debugging. // ��� -debug=libevent������������ libevent ������Ϣ��
    // Otherwise, disable all libevent debugging. // ���򣬽�ֹȫ�� libevent ������Ϣ��
    if (LogAcceptCategory("libevent")) // ���ݵ���ѡ�����õ�����־��¼����
        event_enable_debug_logging(EVENT_DBG_ALL);
    else
        event_enable_debug_logging(EVENT_DBG_NONE);
#endif
#ifdef WIN32 // 3.��ʼ�� libevent �� evhttp �����
    evthread_use_windows_threads();
#else
    evthread_use_pthreads(); // 3.1.��ʼ�� libevent ���߳�֧��
#endif

    base = event_base_new(); // XXX RAII // 3.2.���� event_base ����
    if (!base) {
        LogPrintf("Couldn't create an event_base: exiting\n");
        return false;
    }

    /* Create a new evhttp object to handle requests. */ // 3.3.����һ���µ� evhttp ��������������
    http = evhttp_new(base); // XXX RAII ���� event_base ���� evhttp ����
    if (!http) {
        LogPrintf("couldn't create evhttp. Exiting.\n");
        event_base_free(base);
        return false;
    }

    evhttp_set_timeout(http, GetArg("-rpcservertimeout", DEFAULT_HTTP_SERVER_TIMEOUT)); // 3.4.���� http ����ʱʱ��Ϊ rpc ����ʱ��Ĭ�� 30 ��
    evhttp_set_max_headers_size(http, MAX_HEADERS_SIZE); // http ͷ��С��Ĭ�� 8K
    evhttp_set_max_body_size(http, MAX_SIZE); // ������Ϣ���С��Ĭ�� 32M
    evhttp_set_gencb(http, http_request_cb, NULL); // 3.5.���ô�������Ļص����� http_request_cb

    if (!HTTPBindAddresses(http)) { // 3.6.evhttp_bind_socket(http, "0.0.0.0", port),�󶨷����ַ�Ͷ˿�
        LogPrintf("Unable to bind any endpoint for RPC server\n");
        evhttp_free(http);
        event_base_free(base);
        return false;
    }

    LogPrint("http", "Initialized HTTP server\n"); // evhttp �������˳�ʼ�����
    int workQueueDepth = std::max((long)GetArg("-rpcworkqueue", DEFAULT_HTTP_WORKQUEUE), 1L); // ��ȡ HTTP ����������������Ĭ�� 16����СΪ 1
    LogPrintf("HTTP: creating work queue of depth %d\n", workQueueDepth);

    workQueue = new WorkQueue<HTTPClosure>(workQueueDepth); // 4.�����������
    eventBase = base;
    eventHTTP = http;
    return true; // �ɹ����� true
}

boost::thread threadHTTP;

bool StartHTTPServer()
{
    LogPrint("http", "Starting HTTP server\n");
    int rpcThreads = std::max((long)GetArg("-rpcthreads", DEFAULT_HTTP_THREADS), 1L); // 1.��ȡ RPC �߳�����Ĭ��Ϊ 4������Ϊ 1
    LogPrintf("HTTP: starting %d worker threads\n", rpcThreads);
    threadHTTP = boost::thread(boost::bind(&ThreadHTTP, eventBase, eventHTTP)); // 2.�ɷ��¼�ѭ����http Э������

    for (int i = 0; i < rpcThreads; i++) // 3.���� HTTP �������д����߳�
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
        event_active(ev, 0, 0); // immediately trigger event in main thread // ���������߳��д����¼�
    else
        evtimer_add(ev, tv); // trigger after timeval passed // �ڹ�ȥ timeval ��󴥷�
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
    const struct evkeyvalq* headers = evhttp_request_get_input_headers(req); // ��ȡ����ͷ��
    assert(headers);
    const char* val = evhttp_find_header(headers, hdr.c_str()); // ��ȡͷ��ָ������ֵ
    if (val) // ����ֵ����
        return std::make_pair(true, val); // ��Է���
    else
        return std::make_pair(false, "");
}

std::string HTTPRequest::ReadBody()
{
    struct evbuffer* buf = evhttp_request_get_input_buffer(req); // ��ȡ��������뻺����
    if (!buf)
        return "";
    size_t size = evbuffer_get_length(buf); // ��ȡ��������С
    /** Trivial implementation: if this is ever a performance bottleneck,
     * internal copying can be avoided in multi-segment buffers by using
     * evbuffer_peek and an awkward loop. Though in that case, it'd be even
     * better to not copy into an intermediate string but use a stream
     * abstraction to consume the evbuffer on the fly in the parsing algorithm.
     */ // �򵥵�ʵ�֣��������һ������ƿ����ͨ��ʹ�� evbuffer_peek �ͱ�׾��ѭ�������ڶ�˻������б����ڲ����ơ�
    const char* data = (const char*)evbuffer_pullup(buf, size); // ��ȡָ����С������
    if (!data) // returns NULL in case of empty buffer // ��Ϊ�ջ�����
        return ""; // ���� ""
    std::string rv(data, size); // ����һ���ַ�������
    evbuffer_drain(buf, size); // ���ⲿ�ֻ�ȡ�����ݴӻ�����ǰ���Ƴ�
    return rv; // ���ػ���������
}

void HTTPRequest::WriteHeader(const std::string& hdr, const std::string& value)
{
    struct evkeyvalq* headers = evhttp_request_get_output_headers(req); // ��ȡ����ͷ��ָ��
    assert(headers);
    evhttp_add_header(headers, hdr.c_str(), value.c_str()); // �������Ϣ��ӵ�����ͷ��
}

/** Closure sent to main thread to request a reply to be sent to
 * a HTTP request.
 * Replies must be sent in the main loop in the main http thread,
 * this cannot be done from worker threads.
 */ // ���͵����߳���������Ӧ���ڷ���һ�� HTTP ���󡣷����������� http �̵߳���ѭ���з��ͣ������ܴӹ����߳��з��͡�
void HTTPRequest::WriteReply(int nStatus, const std::string& strReply)
{
    assert(!replySent && req); // ��Ӧδ���� �� ���� http ����
    // Send event to main http thread to send reply message // �����¼����� http �߳���������Ӧ��Ϣ
    struct evbuffer* evb = evhttp_request_get_output_buffer(req); // ��ȡ����������ṹ��ָ��
    assert(evb);
    evbuffer_add(evb, strReply.data(), strReply.size()); // �����Ӧ���ݺʹ�С�����������
    HTTPEvent* ev = new HTTPEvent(eventBase, true, // ����һ�� HTTP �¼�����
        boost::bind(evhttp_send_reply, req, nStatus, (const char*)NULL, (struct evbuffer *)NULL));
    ev->trigger(0); // ���̴������¼�
    replySent = true; // ��Ӧ���ͱ�־��Ϊ true
    req = 0; // transferred back to main thread // �л������߳�
}

CService HTTPRequest::GetPeer()
{
    evhttp_connection* con = evhttp_request_get_connection(req);
    CService peer;
    if (con) {
        // evhttp retains ownership over returned address string
        const char* address = "";
        uint16_t port = 0;
        evhttp_connection_get_peer(con, (char**)&address, &port); // �� HTTP �����л�ȡ�Է� IP �� PORT
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
    switch (evhttp_request_get_command(req)) { // ��ȡ���������ʽ��
    case EVHTTP_REQ_GET: // ������Ӧ�ķ�ʽ
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
    pathHandlers.push_back(HTTPPathHandler(prefix, exactMatch, handler)); // ���봦�����б�
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

