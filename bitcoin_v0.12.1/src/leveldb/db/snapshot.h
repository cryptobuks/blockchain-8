// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#ifndef STORAGE_LEVELDB_DB_SNAPSHOT_H_
#define STORAGE_LEVELDB_DB_SNAPSHOT_H_

#include "leveldb/db.h"

namespace leveldb {

class SnapshotList;

// Snapshots are kept in a doubly-linked list in the DB. // 快照维持数据库中的一个双向链表。
// Each SnapshotImpl corresponds to a particular sequence number. // 每个 SnapshotImpl 对应一个特定的序列号
class SnapshotImpl : public Snapshot { // 存在于一个双向环状链表中的节点
 public:
  SequenceNumber number_;  // const after creation // data 为序列号

 private:
  friend class SnapshotList;

  // SnapshotImpl is kept in a doubly-linked circular list
  SnapshotImpl* prev_;
  SnapshotImpl* next_;

  SnapshotList* list_;                 // just for sanity checks
};

class SnapshotList { // 快照列表
 public:
  SnapshotList() { // 初始化一个双向环状链表的头节点
    list_.prev_ = &list_;
    list_.next_ = &list_;
  }

  bool empty() const { return list_.next_ == &list_; } // 环状链表判空
  SnapshotImpl* oldest() const { assert(!empty()); return list_.next_; } // 返回第一个节点（非伪头节点）
  SnapshotImpl* newest() const { assert(!empty()); return list_.prev_; } // 返回最后一个节点

  const SnapshotImpl* New(SequenceNumber seq) { // 通过序列号新建一个节点
    SnapshotImpl* s = new SnapshotImpl; // 创建一个节点
    s->number_ = seq; // 初始化数据域
    s->list_ = this;
    s->next_ = &list_;
    s->prev_ = list_.prev_;
    s->prev_->next_ = s;
    s->next_->prev_ = s;
    return s;
  }

  void Delete(const SnapshotImpl* s) { // 删除指定节点
    assert(s->list_ == this);
    s->prev_->next_ = s->next_;
    s->next_->prev_ = s->prev_;
    delete s;
  }

 private:
  // Dummy head of doubly-linked list of snapshots
  SnapshotImpl list_; // 快照双链表的伪头节点（不存放数据，序列号）
};

}  // namespace leveldb

#endif  // STORAGE_LEVELDB_DB_SNAPSHOT_H_
