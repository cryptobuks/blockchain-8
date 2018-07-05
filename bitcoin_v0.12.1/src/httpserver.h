// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HTTPSERVER_H
#define BITCOIN_HTTPSERVER_H

#include <string>
#include <stdint.h>
#include <boost/thread.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/function.hpp>

static const int DEFAULT_HTTP_THREADS=4;
static const int DEFAULT_HTTP_WORKQUEUE=16;
static const int DEFAULT_HTTP_SERVER_TIMEOUT=30;

struct evhttp_request;
struct event_base;
class CService;
class HTTPRequest;

/** Initialize HTTP server.
 * Call this before RegisterHTTPHandler or EventBase().
 */ // 初始化 HTTP 服务。在 RegisterHTTPHandler 或 EventBase() 前调用该函数。
bool InitHTTPServer();
/** Start HTTP server.
 * This is separate from InitHTTPServer to give users race-condition-free time
 * to register their handlers between InitHTTPServer and StartHTTPServerStartHTTPServer.
 */ // 启动 HTTP 服务。该操作从 InitHTTPServer 中分离出来为用户提供无竞争条件时间，用于在 InitHTTPServer 和 StartHTTPServer 之间注册其处理函数。
bool StartHTTPServer();
/** Interrupt HTTP server threads */ // 中断 HTTP 服务线程
void InterruptHTTPServer();
/** Stop HTTP server */ // 停止 HTTP 服务
void StopHTTPServer();

/** Handler for requests to a certain HTTP path */ // 用于请求一个确定的 HTTP 路径的处理函数
typedef boost::function<void(HTTPRequest* req, const std::string &)> HTTPRequestHandler;
/** Register handler for prefix.
 * If multiple handlers match a prefix, the first-registered one will
 * be invoked.
 */ // 注册前缀处理函数。若多个处理函数匹配到一个前缀，则调用首个注册的函数。
void RegisterHTTPHandler(const std::string &prefix, bool exactMatch, const HTTPRequestHandler &handler);
/** Unregister handler for prefix */
void UnregisterHTTPHandler(const std::string &prefix, bool exactMatch);

/** Return evhttp event base. This can be used by submodules to
 * queue timers or custom events.
 */
struct event_base* EventBase();

/** In-flight HTTP request.
 * Thin C++ wrapper around evhttp_request.
 */ // 正在进行的 HTTP 请求。evhttp_request 的 C++ 简易包装器。
class HTTPRequest
{
private:
    struct evhttp_request* req;
    bool replySent;

public:
    HTTPRequest(struct evhttp_request* req);
    ~HTTPRequest();

    enum RequestMethod {
        UNKNOWN,
        GET,
        POST,
        HEAD,
        PUT
    };

    /** Get requested URI.
     */
    std::string GetURI();

    /** Get CService (address:ip) for the origin of the http request.
     */
    CService GetPeer();

    /** Get request method.
     */
    RequestMethod GetRequestMethod();

    /**
     * Get the request header specified by hdr, or an empty string.
     * Return an pair (isPresent,string).
     */
    std::pair<bool, std::string> GetHeader(const std::string& hdr);

    /**
     * Read request body. // 读请求体。
     *
     * @note As this consumes the underlying buffer, call this only once.
     * Repeated calls will return an empty string.
     */ // 注：因为这会消耗底层缓冲区，所以仅调用一次。重复调用将返回一个空串。
    std::string ReadBody();

    /**
     * Write output header.
     *
     * @note call this before calling WriteErrorReply or Reply.
     */
    void WriteHeader(const std::string& hdr, const std::string& value);

    /**
     * Write HTTP reply.
     * nStatus is the HTTP status code to send.
     * strReply is the body of the reply. Keep it empty to send a standard message.
     *
     * @note Can be called only once. As this will give the request back to the
     * main thread, do not call any other HTTPRequest methods after calling this.
     */
    void WriteReply(int nStatus, const std::string& strReply = "");
};

/** Event handler closure.
 */
class HTTPClosure
{
public:
    virtual void operator()() = 0;
    virtual ~HTTPClosure() {}
};

/** Event class. This can be used either as an cross-thread trigger or as a timer.
 */ // 事件类。可以用作跨线程触发器或定时器。
class HTTPEvent
{
public:
    /** Create a new event.
     * deleteWhenTriggered deletes this event object after the event is triggered (and the handler called)
     * handler is the handler to call when the event is triggered.
     */
    HTTPEvent(struct event_base* base, bool deleteWhenTriggered, const boost::function<void(void)>& handler);
    ~HTTPEvent();

    /** Trigger the event. If tv is 0, trigger it immediately. Otherwise trigger it after
     * the given time has elapsed.
     */
    void trigger(struct timeval* tv);

    bool deleteWhenTriggered;
    boost::function<void(void)> handler;
private:
    struct event* ev;
};

#endif // BITCOIN_HTTPSERVER_H
