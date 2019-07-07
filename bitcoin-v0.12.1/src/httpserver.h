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

static const int DEFAULT_HTTP_THREADS=4; // HTTP RPC �߳�����Ĭ��Ϊ 4
static const int DEFAULT_HTTP_WORKQUEUE=16;
static const int DEFAULT_HTTP_SERVER_TIMEOUT=30;

struct evhttp_request;
struct event_base;
class CService;
class HTTPRequest;

/** Initialize HTTP server.
 * Call this before RegisterHTTPHandler or EventBase().
 */ // ��ʼ�� HTTP ������ RegisterHTTPHandler �� EventBase() ǰ���øú�����
bool InitHTTPServer();
/** Start HTTP server.
 * This is separate from InitHTTPServer to give users race-condition-free time
 * to register their handlers between InitHTTPServer and StartHTTPServerStartHTTPServer.
 */ // ���� HTTP ���񡣸ò����� InitHTTPServer �з������Ϊ�û��ṩ�޾�������ʱ�䣬������ InitHTTPServer �� StartHTTPServer ֮��ע���䴦������
bool StartHTTPServer();
/** Interrupt HTTP server threads */ // �ж� HTTP �����߳�
void InterruptHTTPServer();
/** Stop HTTP server */ // ֹͣ HTTP ����
void StopHTTPServer();

/** Handler for requests to a certain HTTP path */ // ��������һ��ȷ���� HTTP ·���Ĵ�����
typedef boost::function<void(HTTPRequest* req, const std::string &)> HTTPRequestHandler;
/** Register handler for prefix.
 * If multiple handlers match a prefix, the first-registered one will
 * be invoked.
 */ // ע�ᴦ����ǰ׺�������������ƥ�䵽һ��ǰ׺��������׸�ע��ĺ�����
void RegisterHTTPHandler(const std::string &prefix, bool exactMatch, const HTTPRequestHandler &handler);
/** Unregister handler for prefix */ // ��ע�ᴦ����ǰ׺
void UnregisterHTTPHandler(const std::string &prefix, bool exactMatch);

/** Return evhttp event base. This can be used by submodules to
 * queue timers or custom events.
 */
struct event_base* EventBase();

/** In-flight HTTP request.
 * Thin C++ wrapper around evhttp_request.
 */ // ���ڽ��е� HTTP ����evhttp_request �� C++ ���װ�װ����
class HTTPRequest
{
private:
    struct evhttp_request* req;
    bool replySent;

public:
    HTTPRequest(struct evhttp_request* req);
    ~HTTPRequest();

    enum RequestMethod { // HTTP ����ʽö��
        UNKNOWN, // δ֪
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
     */ // ��ȡ����ʽ��
    RequestMethod GetRequestMethod();

    /**
     * Get the request header specified by hdr, or an empty string.
     * Return an pair (isPresent,string).
     */ // ͨ�� hdr ��ȡ����ͷ��ָ������Ϣ����һ�����ַ���������һ�� pair���Ƿ���ڣ���Ϣ�ַ�������
    std::pair<bool, std::string> GetHeader(const std::string& hdr);

    /**
     * Read request body. // �������塣
     *
     * @note As this consumes the underlying buffer, call this only once.
     * Repeated calls will return an empty string.
     */ // ע����Ϊ������ĵײ㻺���������Խ�����һ�Ρ��ظ����ý�����һ���մ���
    std::string ReadBody();

    /**
     * Write output header.
     *
     * @note call this before calling WriteErrorReply or Reply.
     */ // д���������Ӧ��ͷ��ע���ڵ��� WriteErrorReply �� Reply ǰ���ø��
    void WriteHeader(const std::string& hdr, const std::string& value);

    /**
     * Write HTTP reply.
     * nStatus is the HTTP status code to send.
     * strReply is the body of the reply. Keep it empty to send a standard message.
     *
     * @note Can be called only once. As this will give the request back to the
     * main thread, do not call any other HTTPRequest methods after calling this.
     */ // д�� HTTP ��Ӧ��nStatus �� HTTP ���͵�״̬�롣strReply ����Ӧ�塣Ϊ����������һ����׼��Ϣ��
    void WriteReply(int nStatus, const std::string& strReply = "");
};

/** Event handler closure.
 */ // �¼�����ر�
class HTTPClosure // HTTP �ر������
{
public:
    virtual void operator()() = 0;
    virtual ~HTTPClosure() {}
};

/** Event class. This can be used either as an cross-thread trigger or as a timer.
 */ // �¼��ࡣ�����������̴߳�������ʱ����
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
