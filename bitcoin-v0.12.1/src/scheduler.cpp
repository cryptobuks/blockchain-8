// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "scheduler.h"

#include "reverselock.h"

#include <assert.h>
#include <boost/bind.hpp>
#include <utility>

CScheduler::CScheduler() : nThreadsServicingQueue(0), stopRequested(false), stopWhenEmpty(false)
{
}

CScheduler::~CScheduler()
{
    assert(nThreadsServicingQueue == 0);
}


#if BOOST_VERSION < 105000
static boost::system_time toPosixTime(const boost::chrono::system_clock::time_point& t)
{
    return boost::posix_time::from_time_t(boost::chrono::system_clock::to_time_t(t));
}
#endif

void CScheduler::serviceQueue()
{
    boost::unique_lock<boost::mutex> lock(newTaskMutex); // 1.��������֤�����̰߳�ȫ
    ++nThreadsServicingQueue; // 2.ʹ�ö��е��߳����� 1

    // newTaskMutex is locked throughout this loop EXCEPT
    // when the thread is waiting or when the user's function
    // is called. // ���߳����ڵȴ�������û�����ʱ��newTaskMutex ������ѭ����������
    while (!shouldStop()) { // 3.loop
        try {
            while (!shouldStop() && taskQueue.empty()) { // 3.1.�������Ϊ��
                // Wait until there is something to do. // �ȴ�ֱ���������¿�����������зǿգ���
                newTaskScheduled.wait(lock); // �ȴ���������
            }

            // Wait until either there is a new task, or until // �ȴ�ֱ����һ��������
            // the time of the first item on the queue: // ��ֱ���������׸���Ŀ��ʱ��

// wait_until needs boost 1.50 or later; older versions have timed_wait: // wait_until ��Ҫ boost 1.50 ����°汾���ɰ汾�� timed_wait��
#if BOOST_VERSION < 105000 // ������зǿ�
            while (!shouldStop() && !taskQueue.empty() &&
                   newTaskScheduled.timed_wait(lock, toPosixTime(taskQueue.begin()->first))) { // 3.2.��ȡ������� key��ʱ�䣩�����еȴ�
                // Keep waiting until timeout // �ȴ�ֱ����ʱ
            }
#else // �߰汾 boost ��
            // Some boost versions have a conflicting overload of wait_until that returns void. // һЩ boost �汾��һ�� wait_until ��ͻ�����غ��������� void��
            // Explicitly use a template here to avoid hitting that overload. // ��ȷʹ��ģ���Ա��ⷽʽ�������ء�
            while (!shouldStop() && !taskQueue.empty() &&
                   newTaskScheduled.wait_until<>(lock, taskQueue.begin()->first) != boost::cv_status::timeout) { // 105000 ֮��� boost �汾
                // Keep waiting until timeout // �ȴ�ֱ����ʱ
            }
#endif
            // If there are multiple threads, the queue can empty while we're waiting (another // ��������ж���̣߳����п������ǵȴ�ʱ���
            // thread may service the task we were waiting on). // ����һ���߳̿������ǵȴ�ʱȡ���񣩡�
            if (shouldStop() || taskQueue.empty()) // 3.3.������б����
                continue; // ��������ѭ��

            Function f = taskQueue.begin()->second; // 3.4.��ȡ�����е�һ������
            taskQueue.erase(taskQueue.begin()); // ���������

            {
                // Unlock before calling f, so it can reschedule itself or another task
                // without deadlocking: // �ڵ��� f ֮ǰ�������������������°����Լ����������������������
                reverse_lock<boost::unique_lock<boost::mutex> > rlock(lock); // 3.5.�ڵ��� f ǰ��������ֹ����
                f(); // ִ������
            }
        } catch (...) {
            --nThreadsServicingQueue; // ʹ��������е��߳����� 1
            throw;
        }
    } // end of loop
    --nThreadsServicingQueue; // 4.ʹ��������е��߳����� 1
}

void CScheduler::stop(bool drain)
{
    {
        boost::unique_lock<boost::mutex> lock(newTaskMutex);
        if (drain)
            stopWhenEmpty = true;
        else
            stopRequested = true;
    }
    newTaskScheduled.notify_all();
}

void CScheduler::schedule(CScheduler::Function f, boost::chrono::system_clock::time_point t)
{
    {
        boost::unique_lock<boost::mutex> lock(newTaskMutex);
        taskQueue.insert(std::make_pair(t, f));
    }
    newTaskScheduled.notify_one();
}

void CScheduler::scheduleFromNow(CScheduler::Function f, int64_t deltaSeconds)
{
    schedule(f, boost::chrono::system_clock::now() + boost::chrono::seconds(deltaSeconds));
}

static void Repeat(CScheduler* s, CScheduler::Function f, int64_t deltaSeconds)
{
    f();
    s->scheduleFromNow(boost::bind(&Repeat, s, f, deltaSeconds), deltaSeconds);
}

void CScheduler::scheduleEvery(CScheduler::Function f, int64_t deltaSeconds)
{
    scheduleFromNow(boost::bind(&Repeat, this, f, deltaSeconds), deltaSeconds);
}

size_t CScheduler::getQueueInfo(boost::chrono::system_clock::time_point &first,
                             boost::chrono::system_clock::time_point &last) const
{
    boost::unique_lock<boost::mutex> lock(newTaskMutex);
    size_t result = taskQueue.size();
    if (!taskQueue.empty()) {
        first = taskQueue.begin()->first;
        last = taskQueue.rbegin()->first;
    }
    return result;
}
