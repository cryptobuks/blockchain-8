// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Utilities for converting data from/to strings.
 */
#ifndef BITCOIN_UTILSTRENCODINGS_H
#define BITCOIN_UTILSTRENCODINGS_H

#include <stdint.h>
#include <string>
#include <vector>

#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))
#define UBEGIN(a)           ((unsigned char*)&(a))
#define UEND(a)             ((unsigned char*)&((&(a))[1]))
#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0])) // �����鳤�ȣ�Ԫ�ظ�����

/** This is needed because the foreach macro can't get over the comma in pair<t1, t2> */
#define PAIRTYPE(t1, t2)    std::pair<t1, t2>

/** Used by SanitizeString() */
enum SafeChars
{
    SAFE_CHARS_DEFAULT, //!< The full set of allowed chars
    SAFE_CHARS_UA_COMMENT //!< BIP-0014 subset
};

/**
* Remove unsafe chars. Safe chars chosen to allow simple messages/URLs/email
* addresses, but avoid anything even possibly remotely dangerous like & or >
* @param[in] str    The string to sanitize
* @param[in] rule   The set of safe chars to choose (default: least restrictive)
* @return           A new string without unsafe chars
*/
std::string SanitizeString(const std::string& str, int rule = SAFE_CHARS_DEFAULT);
std::vector<unsigned char> ParseHex(const char* psz);
std::vector<unsigned char> ParseHex(const std::string& str);
signed char HexDigit(char c);
bool IsHex(const std::string& str);
std::vector<unsigned char> DecodeBase64(const char* p, bool* pfInvalid = NULL);
std::string DecodeBase64(const std::string& str);
std::string EncodeBase64(const unsigned char* pch, size_t len);
std::string EncodeBase64(const std::string& str);
std::vector<unsigned char> DecodeBase32(const char* p, bool* pfInvalid = NULL);
std::string DecodeBase32(const std::string& str);
std::string EncodeBase32(const unsigned char* pch, size_t len);
std::string EncodeBase32(const std::string& str);

std::string i64tostr(int64_t n);
std::string itostr(int n);
int64_t atoi64(const char* psz);
int64_t atoi64(const std::string& str);
int atoi(const std::string& str);

/**
 * Convert string to signed 32-bit integer with strict parse error feedback.
 * @returns true if the entire string could be parsed as valid integer,
 *   false if not the entire string could be parsed or when overflow or underflow occurred.
 */
bool ParseInt32(const std::string& str, int32_t *out);

/**
 * Convert string to signed 64-bit integer with strict parse error feedback.
 * @returns true if the entire string could be parsed as valid integer,
 *   false if not the entire string could be parsed or when overflow or underflow occurred.
 */
bool ParseInt64(const std::string& str, int64_t *out);

/**
 * Convert string to double with strict parse error feedback.
 * @returns true if the entire string could be parsed as valid double,
 *   false if not the entire string could be parsed or when overflow or underflow occurred.
 */
bool ParseDouble(const std::string& str, double *out);

template<typename T>
std::string HexStr(const T itbegin, const T itend, bool fSpaces=false)
{
    std::string rv;
    static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    rv.reserve((itend-itbegin)*3); // 3 ����ԭ��һ���ֽ� 8 λ����Ӧ 16 ���Ƶ� 2 λ���ټ����м�Ŀո�
    for(T it = itbegin; it < itend; ++it)
    {
        unsigned char val = (unsigned char)(*it);
        if(fSpaces && it != itbegin) // �ո����ÿһ�� 16 �����ַ���Ĭ�ϲ��ӿո�
            rv.push_back(' ');
        rv.push_back(hexmap[val>>4]); // �� 4 λ
        rv.push_back(hexmap[val&15]); // �� 4 λ
    }

    return rv;
}

template<typename T>
inline std::string HexStr(const T& vch, bool fSpaces=false)
{
    return HexStr(vch.begin(), vch.end(), fSpaces);
}

/**
 * Format a paragraph of text to a fixed width, adding spaces for
 * indentation to any added line.
 */ // ��ʽ���ı�����Ϊ�̶���ȣ�Ϊȫ����ӵ�����������ո�
std::string FormatParagraph(const std::string& in, size_t width = 79, size_t indent = 0);

/**
 * Timing-attack-resistant comparison.
 * Takes time proportional to length
 * of first argument.
 */ // ��ʱ�乥���Աȡ��������һ���������ȳɱ�����ʱ�䡣
template <typename T>
bool TimingResistantEqual(const T& a, const T& b) // �Ƚ��Ƿ����
{
    if (b.size() == 0) return a.size() == 0; // ���ȼ��
    size_t accumulator = a.size() ^ b.size(); // �ۼ������� a �� b ��ȣ���ʼΪ 0
    for (size_t i = 0; i < a.size(); i++) // ���� a
        accumulator |= a[i] ^ b[i%b.size()]; // ����Ƚϣ������ַ���������Ƚϵľ����ַ���
    return accumulator == 0; // ���ۼ�����ֵ����Ϊ 0����ʾ���
}

/** Parse number as fixed point according to JSON number syntax.
 * See http://json.org/number.gif
 * @returns true on success, false on error.
 * @note The result must be in the range (-10^18,10^18), otherwise an overflow error will trigger.
 */ // ���� JSON ���־䷨��������Ϊһ�������㡣�ɹ����� true��ʧ�ܷ��� false�����������ָ����Χ��-10^18,10^18�������򽫴���һ���������
bool ParseFixedPoint(const std::string &val, int decimals, int64_t *amount_out);

#endif // BITCOIN_UTILSTRENCODINGS_H
