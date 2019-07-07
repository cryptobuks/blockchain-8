// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#ifndef STORAGE_LEVELDB_DB_SNAPSHOT_H_
#define STORAGE_LEVELDB_DB_SNAPSHOT_H_

#include "leveldb/db.h"

namespace leveldb {

class SnapshotList;

// Snapshots are kept in a doubly-linked list in the DB. // ����ά�����ݿ��е�һ��˫������
// Each SnapshotImpl corresponds to a particular sequence number. // ÿ�� SnapshotImpl ��Ӧһ���ض������к�
class SnapshotImpl : public Snapshot { // ������һ��˫��״�����еĽڵ�
 public:
  SequenceNumber number_;  // const after creation // data Ϊ���к�

 private:
  friend class SnapshotList;

  // SnapshotImpl is kept in a doubly-linked circular list
  SnapshotImpl* prev_;
  SnapshotImpl* next_;

  SnapshotList* list_;                 // just for sanity checks
};

class SnapshotList { // �����б�
 public:
  SnapshotList() { // ��ʼ��һ��˫��״�����ͷ�ڵ�
    list_.prev_ = &list_;
    list_.next_ = &list_;
  }

  bool empty() const { return list_.next_ == &list_; } // ��״�����п�
  SnapshotImpl* oldest() const { assert(!empty()); return list_.next_; } // ���ص�һ���ڵ㣨��αͷ�ڵ㣩
  SnapshotImpl* newest() const { assert(!empty()); return list_.prev_; } // �������һ���ڵ�

  const SnapshotImpl* New(SequenceNumber seq) { // ͨ�����к��½�һ���ڵ�
    SnapshotImpl* s = new SnapshotImpl; // ����һ���ڵ�
    s->number_ = seq; // ��ʼ��������
    s->list_ = this;
    s->next_ = &list_;
    s->prev_ = list_.prev_;
    s->prev_->next_ = s;
    s->next_->prev_ = s;
    return s;
  }

  void Delete(const SnapshotImpl* s) { // ɾ��ָ���ڵ�
    assert(s->list_ == this);
    s->prev_->next_ = s->next_;
    s->next_->prev_ = s->prev_;
    delete s;
  }

 private:
  // Dummy head of doubly-linked list of snapshots
  SnapshotImpl list_; // ����˫�����αͷ�ڵ㣨��������ݣ����кţ�
};

}  // namespace leveldb

#endif  // STORAGE_LEVELDB_DB_SNAPSHOT_H_
