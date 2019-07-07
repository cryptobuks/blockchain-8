// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DBWRAPPER_H
#define BITCOIN_DBWRAPPER_H

#include "clientversion.h"
#include "serialize.h"
#include "streams.h"
#include "util.h"
#include "utilstrencodings.h"
#include "version.h"

#include <boost/filesystem/path.hpp>

#include <leveldb/db.h>
#include <leveldb/write_batch.h>

class dbwrapper_error : public std::runtime_error
{
public:
    dbwrapper_error(const std::string& msg) : std::runtime_error(msg) {}
};

void HandleError(const leveldb::Status& status) throw(dbwrapper_error);

/** Batch of changes queued to be written to a CDBWrapper */
class CDBBatch // 排队等待写入人 CDBWrapper 的批量更改
{
    friend class CDBWrapper;

private:
    leveldb::WriteBatch batch;
    const std::vector<unsigned char> *obfuscate_key;

public:
    /**
     * @param[in] obfuscate_key    If passed, XOR data with this key.
     */
    CDBBatch(const std::vector<unsigned char> *obfuscate_key) : obfuscate_key(obfuscate_key) { };

    template <typename K, typename V>
    void Write(const K& key, const V& value)
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(ssKey.GetSerializeSize(key));
        ssKey << key;
        leveldb::Slice slKey(&ssKey[0], ssKey.size());

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.reserve(ssValue.GetSerializeSize(value));
        ssValue << value;
        ssValue.Xor(*obfuscate_key);
        leveldb::Slice slValue(&ssValue[0], ssValue.size());

        batch.Put(slKey, slValue);
    }

    template <typename K>
    void Erase(const K& key)
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(ssKey.GetSerializeSize(key));
        ssKey << key;
        leveldb::Slice slKey(&ssKey[0], ssKey.size());

        batch.Delete(slKey);
    }
};

class CDBIterator // 数据库迭代器
{
private:
    leveldb::Iterator *piter; // leveldb 迭代器
    const std::vector<unsigned char> *obfuscate_key;

public:

    /**
     * @param[in] piterIn          The original leveldb iterator.
     * @param[in] obfuscate_key    If passed, XOR data with this key.
     */ // 入参：piterIn 为原始数据库迭代器。obfuscate_key 若通过？则使用键的异或数据。
    CDBIterator(leveldb::Iterator *piterIn, const std::vector<unsigned char>* obfuscate_key) :
        piter(piterIn), obfuscate_key(obfuscate_key) { };
    ~CDBIterator();

    bool Valid(); // 判断数据库迭代器是否有效

    void SeekToFirst();

    template<typename K> void Seek(const K& key) {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION); // 创建数据流对象
        ssKey.reserve(ssKey.GetSerializeSize(key)); // 预开辟空间
        ssKey << key; // 导入数据
        leveldb::Slice slKey(&ssKey[0], ssKey.size()); // 创建 Slice 对象
        piter->Seek(slKey); // 数据库迭代器指向 Slice 对象的首个键的位置
    }

    void Next();

    template<typename K> bool GetKey(K& key) {
        leveldb::Slice slKey = piter->key(); // 获取键并创建 Slice 对象
        try {
            CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION); // 序列化数据
            ssKey >> key; // 导入 key
        } catch (const std::exception&) {
            return false;
        }
        return true; // 获取键成功返回 true
    }

    unsigned int GetKeySize() {
        return piter->key().size();
    }

    template<typename V> bool GetValue(V& value) {
        leveldb::Slice slValue = piter->value(); // 获取当前条目对应的值
        try {
            CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION); // 创建数据流对象
            ssValue.Xor(*obfuscate_key); // 异或
            ssValue >> value; // 导出值
        } catch (const std::exception&) {
            return false;
        }
        return true; // 获取值成功返回 true
    }

    unsigned int GetValueSize() {
        return piter->value().size();
    }

};

class CDBWrapper // （区块）数据库包装器 leveldb
{
private:
    //! custom environment this database is using (may be NULL in case of default environment)
    leveldb::Env* penv;

    //! database options used
    leveldb::Options options;

    //! options used when reading from the database
    leveldb::ReadOptions readoptions;

    //! options used when iterating over values of the database
    leveldb::ReadOptions iteroptions;

    //! options used when writing to the database
    leveldb::WriteOptions writeoptions;

    //! options used when sync writing to the database
    leveldb::WriteOptions syncoptions;

    //! the database itself
    leveldb::DB* pdb;

    //! a key used for optional XOR-obfuscation of the database
    std::vector<unsigned char> obfuscate_key;

    //! the key under which the obfuscation key is stored
    static const std::string OBFUSCATE_KEY_KEY;

    //! the length of the obfuscate key in number of bytes
    static const unsigned int OBFUSCATE_KEY_NUM_BYTES;

    std::vector<unsigned char> CreateObfuscateKey() const;

public:
    /**
     * @param[in] path        Location in the filesystem where leveldb data will be stored.
     * @param[in] nCacheSize  Configures various leveldb cache settings.
     * @param[in] fMemory     If true, use leveldb's memory environment.
     * @param[in] fWipe       If true, remove all existing data.
     * @param[in] obfuscate   If true, store data obfuscated via simple XOR. If false, XOR
     *                        with a zero'd byte array.
     */
    CDBWrapper(const boost::filesystem::path& path, size_t nCacheSize, bool fMemory = false, bool fWipe = false, bool obfuscate = false);
    ~CDBWrapper();

    template <typename K, typename V>
    bool Read(const K& key, V& value) const throw(dbwrapper_error)
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(ssKey.GetSerializeSize(key));
        ssKey << key;
        leveldb::Slice slKey(&ssKey[0], ssKey.size());

        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
        if (!status.ok()) {
            if (status.IsNotFound())
                return false;
            LogPrintf("LevelDB read failure: %s\n", status.ToString());
            HandleError(status);
        }
        try {
            CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
            ssValue.Xor(obfuscate_key);
            ssValue >> value;
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }

    template <typename K, typename V>
    bool Write(const K& key, const V& value, bool fSync = false) throw(dbwrapper_error)
    {
        CDBBatch batch(&obfuscate_key);
        batch.Write(key, value);
        return WriteBatch(batch, fSync); // 往 leveldb 中写数据
    }

    template <typename K>
    bool Exists(const K& key) const throw(dbwrapper_error)
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(ssKey.GetSerializeSize(key));
        ssKey << key;
        leveldb::Slice slKey(&ssKey[0], ssKey.size());

        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
        if (!status.ok()) {
            if (status.IsNotFound())
                return false;
            LogPrintf("LevelDB read failure: %s\n", status.ToString());
            HandleError(status);
        }
        return true;
    }

    template <typename K>
    bool Erase(const K& key, bool fSync = false) throw(dbwrapper_error)
    {
        CDBBatch batch(&obfuscate_key);
        batch.Erase(key);
        return WriteBatch(batch, fSync);
    }

    bool WriteBatch(CDBBatch& batch, bool fSync = false) throw(dbwrapper_error); // 写入一批

    // not available for LevelDB; provide for compatibility with BDB
    bool Flush()
    {
        return true;
    }

    bool Sync() throw(dbwrapper_error)
    {
        CDBBatch batch(&obfuscate_key);
        return WriteBatch(batch, true);
    }

    CDBIterator *NewIterator()
    {
        return new CDBIterator(pdb->NewIterator(iteroptions), &obfuscate_key);
    }

    /**
     * Return true if the database managed by this class contains no entries.
     */
    bool IsEmpty();

    /**
     * Accessor for obfuscate_key.
     */
    const std::vector<unsigned char>& GetObfuscateKey() const;

    /**
     * Return the obfuscate_key as a hex-formatted string.
     */
    std::string GetObfuscateKeyHex() const;

};

#endif // BITCOIN_DBWRAPPER_H

