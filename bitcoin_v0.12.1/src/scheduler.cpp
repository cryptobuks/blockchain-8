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
    boost::unique_lock<boost::mutex> lock(newTaskMutex); // 1.上锁，保证函数线程安全
    ++nThreadsServicingQueue; // 2.使用队列的线程数加 1

    // newTaskMutex is locked throughout this loop EXCEPT
    // when the thread is waiting or when the user's function
    // is called. // 当线程正在等待或调用用户函数时，newTaskMutex 在整个循环中锁定。
    while (!shouldStop()) { // 3.loop
        try {
            while (!shouldStop() && taskQueue.empty()) { // 3.1.任务队列为空
                // Wait until there is something to do. // 等待直到这里有事可做（任务队列非空）。
                newTaskScheduled.wait(lock); // 等待条件满足
            }

            // Wait until either there is a new task, or until // 等待直到有一个新任务，
            // the time of the first item on the queue: // 或直到队列中首个项目超时：

// wait_until needs boost 1.50 or later; older versions have timed_wait: // wait_until 需要 boost 1.50 或更新版本；旧版本有 timed_wait：
#if BOOST_VERSION < 105000 // 任务队列非空
            while (!shouldStop() && !taskQueue.empty() &&
                   newTaskScheduled.timed_wait(lock, toPosixTime(taskQueue.begin()->first))) { // 3.2.获取新任务的 key（时间），进行等待
                // Keep waiting until timeout // 等待直到超时
            }
#else // 高版本 boost 库
            // Some boost versions have a conflicting overload of wait_until that returns void. // 一些 boost 版本有一个 wait_until 冲突的重载函数，返回 void。
            // Explicitly use a template here to avoid hitting that overload. // 精确使用模板以避免方式发生重载。
            while (!shouldStop() && !taskQueue.empty() &&
                   newTaskScheduled.wait_until<>(lock, taskQueue.begin()->first) != boost::cv_status::timeout) { // 105000 之后的 boost 版本
                // Keep waiting until timeout // 等待直到超时
            }
#endif
            // If there are multiple threads, the queue can empty while we're waiting (another // 如果这里有多个线程，队列可在我们等待时清空
            // thread may service the task we were waiting on). // （另一个线程可在我们等待时取任务）。
            if (shouldStop() || taskQueue.empty()) // 3.3.任务队列被清空
                continue; // 跳过本次循环

            Function f = taskQueue.begin()->second; // 3.4.获取队列中第一个任务
            taskQueue.erase(taskQueue.begin()); // 清除该任务

            {
                // Unlock before calling f, so it can reschedule itself or another task
                // without deadlocking: // 在调用 f 之前解锁，以至于它能重新安排自己或其他任务而不会死锁：
                reverse_lock<boost::unique_lock<boost::mutex> > rlock(lock); // 3.5.在调用 f 前解锁，防止死锁
                f(); // 执行任务
            }
        } catch (...) {
            --nThreadsServicingQueue; // 使用任务队列的线程数减 1
            throw;
        }
    } // end of loop
    --nThreadsServicingQueue; // 4.使用任务队列的线程数减 1
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
