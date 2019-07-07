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
//   matches the original. // ���ԣ���һ���ַ���խת��Ϊ����֤����Ƿ�ƥ��ԭʼ�ַ���
bool sanity_test_widen(char testchar)
{
    const std::ctype<char>& test(std::use_facet<std::ctype<char> >(std::locale())); // ��ʼ��������������
    return test.narrow(test.widen(testchar), 'b') == testchar; // ת�������ַ�Ϊ���ַ���ת��Ϊխ�ַ�����ԭ�ַ��Ƚϣ�'b' Ϊת��ʧ��ʱ���ɵ�Ĭ��ֵ
}

// trigger: use list::push_back and list::pop_back to trigger _M_hook and
//   _M_unhook.
// test: Push a sequence of integers into a list. Pop them off and verify that
//   they match the original sequence. // ���ԣ�����һϵ��������һ����������������֤��ԭʼ�����Ƿ�ƥ�䡣
bool sanity_test_list(unsigned int size) // 100
{
    std::list<unsigned int> test; // ������˫��ѭ������
    for (unsigned int i = 0; i != size; ++i) // ˳����������
        test.push_back(i + 1);

    if (test.size() != size) // ��֤��С
        return false;

    while (!test.empty()) { // ������ǿ�
        if (test.back() != test.size()) // ��Ƚ�ԭ���бȽ�
            return false;
        test.pop_back(); // ����
    }
    return true; // ƥ��ɹ����� true
}

} // anon namespace

// trigger: string::at(x) on an empty string to trigger __throw_out_of_range_fmt.
// test: force std::string to throw an out_of_range exception. Verify that
//   it's caught correctly. // ���ԣ�ǿ�� std::string �׳� out_of_range ������Χ�쳣����֤�Ƿ���ȷ������쳣��
bool sanity_test_range_fmt()
{
    std::string test; // ���� std::string �ն���
    try {
        test.at(1); // ��ȡλ�� 1 ���ַ������ã�ִ�б߽��飬������Ч���׳� std::out_of_range ���͵��쳣
    } catch (const std::out_of_range&) { // ������ std::out_of_range �쳣
        return true; // ���� true
    } catch (...) {
    }
    return false; // ���򷵻� false
}

bool glibcxx_sanity_test()
{
    return sanity_test_widen('a') && sanity_test_list(100) && sanity_test_range_fmt(); // ���Կ�խ�ַ���ת��������Χ��ʽ
}
