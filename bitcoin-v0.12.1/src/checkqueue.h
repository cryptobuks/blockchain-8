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
  */ // ����ִ����֤�Ķ��С�����֤������ T ��ʾ�������ṩһ��������������������ز����͡�
template <typename T> // ����һ���̣߳���������������֤�������У����Ǳ� N-1 �������̴߳��������߳������ӹ���������ʱ���빤������Ϊ�� N �������̣߳�ֱ��ȫ��������ɡ�
class CCheckQueue // ���������ģ��
{
private:
    //! Mutex to protect the inner state
    boost::mutex mutex; // �����ڲ�״̬�Ļ�����

    //! Worker threads block on this when out of work
    boost::condition_variable condWorker; // �����̵߳���������

    //! Master thread blocks on this when out of work
    boost::condition_variable condMaster; // ���̵߳���������

    //! The queue of elements to be processed. // �������Ԫ�ض��С�
    //! As the order of booleans doesn't matter, it is used as a LIFO (stack)
    std::vector<T> queue; // ��Ϊ������˳����Ҫ���������� LIFO ��ջ��

    //! The number of workers (including the master) that are idle.
    int nIdle; // ���еĹ����߳������������̣߳���

    //! The total number of workers (including the master).
    int nTotal; // �����߳��������������̣߳���

    //! The temporary evaluation result.
    bool fAllOk; // ��ʱ���������

    /**
     * Number of verifications that haven't completed yet.
     * This includes elements that are no longer queued, but still in the
     * worker's own batches.
     */ // ��δ��ɵ���֤�����������ڶ����е�Ԫ�أ������ڹ����߳��Լ��������С�
    unsigned int nTodo;

    //! Whether we're shutting down.
    bool fQuit; // �����Ƿ�رա�

    //! The maximum number of elements to be processed in one batch
    unsigned int nBatchSize; // һ����Ҫ��������Ԫ����

    /** Internal function that does bulk of the verification work. */
    bool Loop(bool fMaster = false) // ��������֤�������ڲ�������
    {
        boost::condition_variable& cond = fMaster ? condMaster : condWorker; // 1.����������Ĭ��Ϊ�����̵߳�
        std::vector<T> vChecks; // ����б�
        vChecks.reserve(nBatchSize); // Ԥ����һ��Ҫ�������ռ�
        unsigned int nNow = 0; // ����ʱ�䣬��ʼ��Ϊ 0
        bool fOk = true; // ״̬��־����ʼ��Ϊ true
        do {
            {
                boost::unique_lock<boost::mutex> lock(mutex); // 2.����
                // first do the clean-up of the previous loop run (allowing us to do it in the same critsect) // 3.����������һ��ѭ�����У�������������ͬ���ٽ���Դ�����У�
                if (nNow) { // ����ǰʱ��� 0��˵�����״�ѭ��
                    fAllOk &= fOk; // ����״̬
                    nTodo -= nNow; // �������ɵ���֤��
                    if (nTodo == 0 && !fMaster) // ����֤��Ϊ 0 �� ���������߳�
                        // We processed the last element; inform the master it can exit and return the result // ���Ǵ������һ��Ԫ�أ�֪ͨ���߳��������˳������ؽ��
                        condMaster.notify_one(); // �����������߳�������֪ͨ���߳�
                } else { // �״�ѭ��
                    // first iteration // �״ε���
                    nTotal++; // �����߳����� 1
                }
                // logically, the do loop starts here // 4.�����ϣ�do ѭ�������￪ʼ
                while (queue.empty()) { // ����֤���У��б�Ϊ��
                    if ((fMaster || fQuit) && nTodo == 0) { // �������߳� �� ��Ҫ�˳� ��δ�����Ϊ 0
                        nTotal--; // �����߳������� 1
                        bool fRet = fAllOk; // ��ȡ����״̬
                        // reset the status for new work later // �Ժ������¹����߳�״̬
                        if (fMaster) // ��Ϊ���߳�
                            fAllOk = true; // ״̬��Ϊ true
                        // return the current status
                        return fRet; // ���ص�ǰ״̬
                    }
                    nIdle++; // �����߳����� 1
                    cond.wait(lock); // wait // �߳������ȴ���
                    nIdle--; // һ������������߳����� 1
                }
                // Decide how many work units to process now. // 5.��������Ҫ������ٹ�����Ԫ��
                // * Do not try to do everything at once, but aim for increasingly smaller batches so // ��Ҫ��ͼһ��������е����飬
                //   all workers finish approximately simultaneously. // �����ڲ������ӵ�С�������������̻߳���ͬʱ���
                // * Try to account for idle jobs which will instantly start helping. // ���Լ�¼������ʼ�����Ŀ��й�����
                // * Don't do batches smaller than 1 (duh), or larger than nBatchSize. // ��Ҫ��С�� 1��duh�������Σ������ nBatchSize �����Ρ�
                nNow = std::max(1U, std::min(nBatchSize, (unsigned int)queue.size() / (nTotal + nIdle + 1)));
                vChecks.resize(nNow); // ���ü���б��С
                for (unsigned int i = 0; i < nNow; i++) { // ��������б�
                    // We want the lock on the mutex to be as short as possible, so swap jobs from the global
                    // queue to the local batch vector instead of copying.
                    vChecks[i].swap(queue.back()); // ȡ������Ԫ�ض������һ��Ԫ�������б���׸�Ԫ�ؽ���
                    queue.pop_back(); // ��βԪ�س���
                }
                // Check whether we need to do work at all // ��������Ƿ���Ҫ��ɹ���
                fOk = fAllOk; // ����״̬λ
            }
            // execute work // 6.ִ�й���
            BOOST_FOREACH (T& check, vChecks) // ��������б�
                if (fOk) // ����Ҫ���
                    fOk = check(); // ִ�иü�麯��
            vChecks.clear(); // ��ռ���б�
        } while (true); // do loop
    }

public:
    //! Create a new check queue // ����һ���µļ�����
    CCheckQueue(unsigned int nBatchSizeIn) : nIdle(0), nTotal(0), fAllOk(true), nTodo(0), fQuit(false), nBatchSize(nBatchSizeIn) {}

    //! Worker thread // �����߳�
    void Thread()
    {
        Loop(); // ���� Loop ����ѭ��
    }

    //! Wait until execution finishes, and return whether all evaluations were successful.
    bool Wait() // �ȴ�ֱ��ִ�н������������������Ƿ�ɹ���
    {
        return Loop(true);
    }

    //! Add a batch of checks to the queue // ���һ���μ��鵽����
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
