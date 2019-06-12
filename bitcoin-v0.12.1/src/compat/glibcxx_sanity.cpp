// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <list>
#include <locale>
#include <stdexcept>

namespace
{
// trigger: use ctype<char>::widen to trigger ctype<char>::_M_widen_init().
// test: convert a char from narrow to wide and back. Verify that the result
//   matches the original. // 测试：把一个字符从窄转换为宽。验证结果是否匹配原始字符。
bool sanity_test_widen(char testchar)
{
    const std::ctype<char>& test(std::use_facet<std::ctype<char> >(std::locale())); // 初始化本地区域设置
    return test.narrow(test.widen(testchar), 'b') == testchar; // 转换测试字符为宽字符再转换为窄字符，与原字符比较，'b' 为转换失败时生成的默认值
}

// trigger: use list::push_back and list::pop_back to trigger _M_hook and
//   _M_unhook.
// test: Push a sequence of integers into a list. Pop them off and verify that
//   they match the original sequence. // 测试：推送一系列整数到一个链表。弹出它们验证与原始序列是否匹配。
bool sanity_test_list(unsigned int size) // 100
{
    std::list<unsigned int> test; // 测试用双向循环链表
    for (unsigned int i = 0; i != size; ++i) // 顺序推入整数
        test.push_back(i + 1);

    if (test.size() != size) // 验证大小
        return false;

    while (!test.empty()) { // 若链表非空
        if (test.back() != test.size()) // 与比较原数列比较
            return false;
        test.pop_back(); // 弹出
    }
    return true; // 匹配成功返回 true
}

} // anon namespace

// trigger: string::at(x) on an empty string to trigger __throw_out_of_range_fmt.
// test: force std::string to throw an out_of_range exception. Verify that
//   it's caught correctly. // 测试：强制 std::string 抛出 out_of_range 超出范围异常。验证是否正确捕获该异常。
bool sanity_test_range_fmt()
{
    std::string test; // 创建 std::string 空对象
    try {
        test.at(1); // 获取位置 1 处字符的引用，执行边界检查，访问无效将抛出 std::out_of_range 类型的异常
    } catch (const std::out_of_range&) { // 若捕获 std::out_of_range 异常
        return true; // 返回 true
    } catch (...) {
    }
    return false; // 否则返回 false
}

bool glibcxx_sanity_test()
{
    return sanity_test_widen('a') && sanity_test_list(100) && sanity_test_range_fmt(); // 测试宽窄字符互转、链表、范围格式
}
