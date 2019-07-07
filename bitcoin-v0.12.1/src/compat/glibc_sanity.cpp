// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include <cstddef>

#if defined(HAVE_SYS_SELECT_H)
#include <sys/select.h>
#endif

extern "C" void* memcpy(void* a, const void* b, size_t c);
void* memcpy_int(void* a, const void* b, size_t c)
{
    return memcpy(a, b, c);
}

namespace
{
// trigger: Use the memcpy_int wrapper which calls our internal memcpy.
//   A direct call to memcpy may be optimized away by the compiler.
// test: Fill an array with a sequence of integers. memcpy to a new empty array. // 测试：用一系列证数填充数组。内存拷贝该数组到一个新的空数组。
//   Verify that the arrays are equal. Use an odd size to decrease the odds of // 验证数组是否相等。
//   the call being optimized away. // 使用奇数大小可降低被优化的机率。
template <unsigned int T>
bool sanity_test_memcpy()
{
    unsigned int memcpy_test[T]; // 1025
    unsigned int memcpy_verify[T] = {};
    for (unsigned int i = 0; i != T; ++i) // 遍历填充
        memcpy_test[i] = i;

    memcpy_int(memcpy_verify, memcpy_test, sizeof(memcpy_test)); // 内存拷贝

    for (unsigned int i = 0; i != T; ++i) { // 遍历
        if (memcpy_verify[i] != i) // 逐个验证
            return false; // 若不等返回 false
    }
    return true; // 若完全相等返回 true
}

#if defined(HAVE_SYS_SELECT_H)
// trigger: Call FD_SET to trigger __fdelt_chk. FORTIFY_SOURCE must be defined
//   as >0 and optimizations must be set to at least -O2.
// test: Add a file descriptor to an empty fd_set. Verify that it has been
//   correctly added. // 测试：把文件描述符添加到空的 fd_set。验证其是否正确添加。
bool sanity_test_fdelt()
{
    fd_set fds; // 文件描述符集对象
    FD_ZERO(&fds); // 清空
    FD_SET(0, &fds); // 设置标准输入到该集合
    return FD_ISSET(0, &fds); // 检查标准输入描述符是否在该集合中
}
#endif

} // anon namespace

bool glibc_sanity_test()
{
#if defined(HAVE_SYS_SELECT_H)
    if (!sanity_test_fdelt()) // 测试文件描述符集合
        return false;
#endif
    return sanity_test_memcpy<1025>(); // 测试内存拷贝
}
