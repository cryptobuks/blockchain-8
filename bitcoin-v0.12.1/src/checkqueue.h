// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKQUEUE_H
#define BITCOIN_CHECKQUEUE_H

#include <algorithm>
#include <vector>

#include <boost/foreach.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>

template <typename T>
class CCheckQueueControl;

/** 
 * Queue for verifications that have to be performed.
  * The verifications are represented by a type T, which must provide an
  * operator(), returning a bool.
  *
  * One thread (the master) is assumed to push batches of verifications
  * onto the queue, where they are processed by N-1 worker threads. When
  * the master is done adding work, it temporarily joins the worker pool
  * as an N'th worker, until all jobs are done.
  */ // 必须执行验证的队列。该验证由类型 T 表示，必须提供一个函数调用运算符，返回布尔型。
template <typename T> // 假设一个线程（主）推送批量验证到队列中，它们被 N-1 个工作线程处理。当主线程完成添加工作，它临时加入工作池作为第 N 个工作线程，直到全部工作完成。
class CCheckQueue // 检验队列类模板
{
private:
    //! Mutex to protect the inner state
    boost::mutex mutex; // 保护内部状态的互斥锁

    //! Worker threads block on this when out of work
    boost::condition_variable condWorker; // 工作线程的条件变量

    //! Master thread blocks on this when out of work
    boost::condition_variable condMaster; // 主线程的条件变量

    //! The queue of elements to be processed. // 被处理的元素队列。
    //! As the order of booleans doesn't matter, it is used as a LIFO (stack)
    std::vector<T> queue; // 因为布尔的顺序不重要，它被用作 LIFO （栈）

    //! The number of workers (including the master) that are idle.
    int nIdle; // 空闲的工作线程数（包含主线程）。

    //! The total number of workers (including the master).
    int nTotal; // 工作线程总数（包含主线程）。

    //! The temporary evaluation result.
    bool fAllOk; // 临时评估结果。

    /**
     * Number of verifications that haven't completed yet.
     * This includes elements that are no longer queued, but still in the
     * worker's own batches.
     */ // 还未完成的验证数。包含不在队列中的元素，但仍在工作线程自己的批次中。
    unsigned int nTodo;

    //! Whether we're shutting down.
    bool fQuit; // 我们是否关闭。

    //! The maximum number of elements to be processed in one batch
    unsigned int nBatchSize; // 一批中要处理的最大元素数

    /** Internal function that does bulk of the verification work. */
    bool Loop(bool fMaster = false) // 做大量验证工作的内部函数。
    {
        boost::condition_variable& cond = fMaster ? condMaster : condWorker; // 1.条件变量，默认为工作线程的
        std::vector<T> vChecks; // 检查列表
        vChecks.reserve(nBatchSize); // 预开辟一批要检测的最大空间
        unsigned int nNow = 0; // 当下时间，初始化为 0
        bool fOk = true; // 状态标志，初始化为 true
        do {
            {
                boost::unique_lock<boost::mutex> lock(mutex); // 2.上锁
                // first do the clean-up of the previous loop run (allowing us to do it in the same critsect) // 3.首先清理上一次循环运行（允许我们在相同的临界资源中运行）
                if (nNow) { // 若当前时间非 0，说明非首次循环
                    fAllOk &= fOk; // 更新状态
                    nTodo -= nNow; // 计算待完成的验证数
                    if (nTodo == 0 && !fMaster) // 若验证数为 0 且 非主工作线程
                        // We processed the last element; inform the master it can exit and return the result // 我们处理最后一个元素；通知主线程它可以退出并返回结果
                        condMaster.notify_one(); // 激活主工作线程条件，通知主线程
                } else { // 首次循环
                    // first iteration // 首次迭代
                    nTotal++; // 工作线程数加 1
                }
                // logically, the do loop starts here // 4.理论上，do 循环从这里开始
                while (queue.empty()) { // 若验证队列（列表）为空
                    if ((fMaster || fQuit) && nTodo == 0) { // 主工作线程 或 将要退出 且未完成数为 0
                        nTotal--; // 工作线程总数减 1
                        bool fRet = fAllOk; // 获取最终状态
                        // reset the status for new work later // 稍后重置新工作线程状态
                        if (fMaster) // 若为主线程
                            fAllOk = true; // 状态置为 true
                        // return the current status
                        return fRet; // 返回当前状态
                    }
                    nIdle++; // 空闲线程数加 1
                    cond.wait(lock); // wait // 线程条件等待锁
                    nIdle--; // 一旦被激活，空闲线程数减 1
                }
                // Decide how many work units to process now. // 5.决定现在要处理多少工作单元。
                // * Do not try to do everything at once, but aim for increasingly smaller batches so // 不要试图一次完成所有的事情，
                //   all workers finish approximately simultaneously. // 但对于不断增加的小批次以至所有线程基本同时完成
                // * Try to account for idle jobs which will instantly start helping. // 尝试记录即将开始帮助的空闲工作。
                // * Don't do batches smaller than 1 (duh), or larger than nBatchSize. // 不要做小于 1（duh）的批次，或大于 nBatchSize 的批次。
                nNow = std::max(1U, std::min(nBatchSize, (unsigned int)queue.size() / (nTotal + nIdle + 1)));
                vChecks.resize(nNow); // 重置检查列表大小
                for (unsigned int i = 0; i < nNow; i++) { // 遍历检查列表
                    // We want the lock on the mutex to be as short as possible, so swap jobs from the global
                    // queue to the local batch vector instead of copying.
                    vChecks[i].swap(queue.back()); // 取被处理元素队列最后一个元素与检测列表的首个元素交换
                    queue.pop_back(); // 队尾元素出队
                }
                // Check whether we need to do work at all // 检查我们是否需要完成工作
                fOk = fAllOk; // 设置状态位
            }
            // execute work // 6.执行工作
            BOOST_FOREACH (T& check, vChecks) // 遍历检查列表
                if (fOk) // 若需要检查
                    fOk = check(); // 执行该检查函数
            vChecks.clear(); // 清空检查列表
        } while (true); // do loop
    }

public:
    //! Create a new check queue // 创建一个新的检查队列
    CCheckQueue(unsigned int nBatchSizeIn) : nIdle(0), nTotal(0), fAllOk(true), nTodo(0), fQuit(false), nBatchSize(nBatchSizeIn) {}

    //! Worker thread // 工作线程
    void Thread()
    {
        Loop(); // 调用 Loop 进行循环
    }

    //! Wait until execution finishes, and return whether all evaluations were successful.
    bool Wait() // 等待直到执行结束，返回所有评估是否成功。
    {
        return Loop(true);
    }

    //! Add a batch of checks to the queue // 添加一批次检验到队列
    void Add(std::vector<T>& vChecks)
    {
        boost::unique_lock<boost::mutex> lock(mutex);
        BOOST_FOREACH (T& check, vChecks) {
            queue.push_back(T());
            check.swap(queue.back());
        }
        nTodo += vChecks.size();
        if (vChecks.size() == 1)
            condWorker.notify_one();
        else if (vChecks.size() > 1)
            condWorker.notify_all();
    }

    ~CCheckQueue()
    {
    }

    bool IsIdle()
    {
        boost::unique_lock<boost::mutex> lock(mutex);
        return (nTotal == nIdle && nTodo == 0 && fAllOk == true);
    }

};

/** 
 * RAII-style controller object for a CCheckQueue that guarantees the passed
 * queue is finished before continuing.
 */
template <typename T>
class CCheckQueueControl
{
private:
    CCheckQueue<T>* pqueue;
    bool fDone;

public:
    CCheckQueueControl(CCheckQueue<T>* pqueueIn) : pqueue(pqueueIn), fDone(false)
    {
        // passed queue is supposed to be unused, or NULL
        if (pqueue != NULL) {
            bool isIdle = pqueue->IsIdle();
            assert(isIdle);
        }
    }

    bool Wait()
    {
        if (pqueue == NULL)
            return true;
        bool fRet = pqueue->Wait();
        fDone = true;
        return fRet;
    }

    void Add(std::vector<T>& vChecks)
    {
        if (pqueue != NULL)
            pqueue->Add(vChecks);
    }

    ~CCheckQueueControl()
    {
        if (!fDone)
            Wait();
    }
};

#endif // BITCOIN_CHECKQUEUE_H
