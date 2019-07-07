// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SUPPORT_PAGELOCKER_H
#define BITCOIN_SUPPORT_PAGELOCKER_H

#include "support/cleanse.h"

#include <map>

#include <boost/thread/mutex.hpp>
#include <boost/thread/once.hpp>

/**
 * Thread-safe class to keep track of locked (ie, non-swappable) memory pages.
 *
 * Memory locks do not stack, that is, pages which have been locked several times by calls to mlock()
 * will be unlocked by a single call to munlock(). This can result in keying material ending up in swap when
 * those functions are used naively. This class simulates stacking memory locks by keeping a counter per page.
 *
 * @note By using a map from each page base address to lock count, this class is optimized for
 * small objects that span up to a few pages, mostly smaller than a page. To support large allocations,
 * something like an interval tree would be the preferred data structure.
 */ // 用于跟踪锁定（即不可交换）的内存页的线程安全类。
template <class Locker>
class LockedPageManagerBase
{
public:
    LockedPageManagerBase(size_t page_size) : page_size(page_size)
    {
        // Determine bitmask for extracting page from address
        assert(!(page_size & (page_size - 1))); // size must be power of two
        page_mask = ~(page_size - 1);
    }

    ~LockedPageManagerBase()
    {
    }


    // For all pages in affected range, increase lock count // 对于受影响范围内的所有页面，增加锁定计数
    void LockRange(void* p, size_t size)
    {
        boost::mutex::scoped_lock lock(mutex); // 区域锁
        if (!size) // 若锁定区域大小为 0
            return; // 直接返回
        const size_t base_addr = reinterpret_cast<size_t>(p); // 强制转换
        const size_t start_page = base_addr & page_mask; // 计算开始页
        const size_t end_page = (base_addr + size - 1) & page_mask; // 计算结束页
        for (size_t page = start_page; page <= end_page; page += page_size) { // 遍历每一页
            Histogram::iterator it = histogram.find(page); // 在页面基址映射列表中查询
            if (it == histogram.end()) // Newly locked page // 若未找到，说明还未上锁
            {
                locker.Lock(reinterpret_cast<void*>(page), page_size); // 锁定内存页
                histogram.insert(std::make_pair(page, 1)); // 插入页面基址映射列表
            } else // Page was already locked; increase counter // 若找到了，说明页面已锁，仅增加锁定计数
            {
                it->second += 1; // 锁定计数加 1
            }
        }
    }

    // For all pages in affected range, decrease lock count // 对于受影响范围内的所有页面，减少锁定计数
    void UnlockRange(void* p, size_t size)
    {
        boost::mutex::scoped_lock lock(mutex); // 区域锁
        if (!size) // 若解锁区域大小为 0
            return; // 直接返回
        const size_t base_addr = reinterpret_cast<size_t>(p); // 强制转换
        const size_t start_page = base_addr & page_mask; // 计算开始页
        const size_t end_page = (base_addr + size - 1) & page_mask; // 计算结束页
        for (size_t page = start_page; page <= end_page; page += page_size) { // 遍历每一页
            Histogram::iterator it = histogram.find(page); // 在页面基址映射列表中查询
            assert(it != histogram.end()); // Cannot unlock an area that was not locked // 若未找到，则报错
            // Decrease counter for page, when it is zero, the page will be unlocked // 否则，减少其锁定次数，当次数为 0 时，页面将解锁
            it->second -= 1; // 锁定次数减 1
            if (it->second == 0) // Nothing on the page anymore that keeps it locked // 页面上没有上锁
            {
                // Unlock page and remove the count from histogram // 解锁页面并基址映射列表中从移除该项
                locker.Unlock(reinterpret_cast<void*>(page), page_size); // 先对该内存页解锁
                histogram.erase(it); // 从映射列表中移除
            }
        }
    }

    // Get number of locked pages for diagnostics
    int GetLockedPageCount()
    {
        boost::mutex::scoped_lock lock(mutex);
        return histogram.size();
    }

private:
    Locker locker; // 内存页加解锁对象
    boost::mutex mutex; // 互斥锁
    size_t page_size, page_mask; // 页面大小，页面掩码
    // map of page base address to lock count // 用于锁定计数的页面基址的映射
    typedef std::map<size_t, int> Histogram; // <页面起始地址， 锁定次数>
    Histogram histogram; // 页面基址映射列表
};


/**
 * OS-dependent memory page locking/unlocking.
 * Defined as policy class to make stubbing for test possible.
 */ // 依赖操作系统的内存页锁定/解锁。定义为策略类，为测试做准备。
class MemoryPageLocker
{
public:
    /** Lock memory pages.
     * addr and len must be a multiple of the system page size
     */ // 锁定内存页。地址和长度必须是系统页的倍数
    bool Lock(const void* addr, size_t len);
    /** Unlock memory pages.
     * addr and len must be a multiple of the system page size
     */ // 解锁内存页。地址和长度必须是系统页的倍数
    bool Unlock(const void* addr, size_t len);
};

/**
 * Singleton class to keep track of locked (ie, non-swappable) memory pages, for use in
 * std::allocator templates.
 *
 * Some implementations of the STL allocate memory in some constructors (i.e., see
 * MSVC's vector<T> implementation where it allocates 1 byte of memory in the allocator.)
 * Due to the unpredictable order of static initializers, we have to make sure the
 * LockedPageManager instance exists before any other STL-based objects that use
 * secure_allocator are created. So instead of having LockedPageManager also be
 * static-initialized, it is created on demand.
 */ // 用于跟踪锁定（即不可交换）的内存页的单例类，用于 std::allocator 模板中。
class LockedPageManager : public LockedPageManagerBase<MemoryPageLocker>
{
public:
    static LockedPageManager& Instance() // 获取单例对象的引用
    {
        boost::call_once(LockedPageManager::CreateInstance, LockedPageManager::init_flag); // 保证只执行一次 LockedPageManager::CreateInstance 函数，线程安全
        return *LockedPageManager::_instance; // 返回单例对象
    }

private:
    LockedPageManager();

    static void CreateInstance() // 创建实例
    {
        // Using a local static instance guarantees that the object is initialized // 使用局部静态实例可确保在首次需要时初始化对象，
        // when it's first needed and also deinitialized after all objects that use // 并在所有使用它的对象使用完成后对其进行取消初始化。
        // it are done with it.  I can think of one unlikely scenario where we may // 我可以想到一个不太可能出现静态取消初始化顺序/问题的情况，
        // have a static deinitialization order/problem, but the check in // 但检查 LockedPageManagerBase 类的析构函数可以帮助我们侦测这种情况是否会发生。
        // LockedPageManagerBase's destructor helps us detect if that ever happens.
        static LockedPageManager instance; // 创建局部静态单例对象
        LockedPageManager::_instance = &instance;
    }

    static LockedPageManager* _instance; // 实例指针
    static boost::once_flag init_flag; // 初始化标志（静态初始化为 BOOST_ONCE_INIT）
};

//
// Functions for directly locking/unlocking memory objects.
// Intended for non-dynamically allocated structures.
// // 用于直接锁定/解锁内存对象的函数。用于非动态分配的结构。
template <typename T>
void LockObject(const T& t)
{
    LockedPageManager::Instance().LockRange((void*)(&t), sizeof(T)); // 锁定
}

template <typename T>
void UnlockObject(const T& t)
{
    memory_cleanse((void*)(&t), sizeof(T)); // 先清空指定区域的数据
    LockedPageManager::Instance().UnlockRange((void*)(&t), sizeof(T)); // 解锁
}

#endif // BITCOIN_SUPPORT_PAGELOCKER_H
