// Copyright 2015 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef SYZYGY_REFINERY_PROCESS_STATE_PROCESS_STATE_H_
#define SYZYGY_REFINERY_PROCESS_STATE_PROCESS_STATE_H_

#include <iterator>
#include <map>
#include <vector>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/process_state/record_traits.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

// A process state is a cross-platform representation of the memory contents
// and other state of a process, typically obtained obtained from a post-mortem
// crash minidump. A process state typically contains only a partial state of
// the process.
// It is comprised of a number of layers, each representing some aspect of the
// process (eg raw bytes, stack, stack frames, heap snippets, typed blocks,
// loaded libraries, etc.).
// Each layer is a bag of records, where each record covers part of the
// process' virtual memory space, and contains data specific to that layer and
// range. Each layer and the data associated with a record is a protobuf of
// a type appropriate to the layer.
class ProcessState {
 public:
  template <typename RecordType> class Layer;
  template <typename RecordType> class Record;

  ProcessState();
  ~ProcessState();

  // Finds layer of type @p RecordType if one exists.
  // @param layer on success, the returned layer.
  // @returns true on success, false if layer doesn't exist.
  template<typename RecordType>
  bool FindLayer(scoped_refptr<Layer<RecordType>>* layer);

  // Finds or creates a layer of type @p RecordType.
  // @param layer the returned layer.
  template<typename RecordType>
  void FindOrCreateLayer(scoped_refptr<Layer<RecordType>>* layer);

  // Finds the stack record of the thread of id @p thread_id.
  // @param thread_id the id of the thread.
  // @param record on success, the returned stack record.
  // @returns true on success, false if record doesn't exist.
  bool FindStackRecord(size_t thread_id,
                       scoped_refptr<Record<Stack>>* record);

 private:
  class LayerBase;

  template<typename RecordType>
  void CreateLayer(scoped_refptr<Layer<RecordType>>* layer);

  std::map<RecordId, scoped_refptr<LayerBase>> layers_;

  DISALLOW_COPY_AND_ASSIGN(ProcessState);
};

// An layer is one view on a process (eg raw bytes, stack, stack frames,
// typed blocks). It's a bag of records that span some part of the process'
// address space.
class ProcessState::LayerBase : public base::RefCounted<LayerBase> {
 public:
  LayerBase() {}

 protected:
  friend class base::RefCounted<LayerBase>;
  virtual ~LayerBase() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(LayerBase);
};

// An individual record of a layer. Contains the data associated with the
// record as a protobuffer.
template <typename RecordType>
class ProcessState::Record : public base::RefCounted<Record<RecordType>> {
 public:
  // @pre @p range must be a valid range.
  explicit Record(AddressRange range) : range_(range) {
    DCHECK(range.IsValid());
  }

  // @name Accessors.
  // @{
  AddressRange range() const { return range_; }
  RecordType* mutable_data() { return &data_; }
  const RecordType& data() { return data_; }
  // @}

 private:
  friend class base::RefCounted<Record<RecordType>>;
  ~Record() {}

  AddressRange range_;
  RecordType data_;

  DISALLOW_COPY_AND_ASSIGN(Record);
};

template <typename RecordType> class Iterator;

template <typename RecordType>
class ProcessState::Layer : public ProcessState::LayerBase {
 public:
  typedef scoped_refptr<Record<RecordType>> RecordPtr;
  typedef Iterator<RecordType> Iterator;

  // @pre @p range must be a valid.
  void CreateRecord(AddressRange range, RecordPtr* record);

  // Gets records located at |addr|.
  // @param addr the address records should must be located at.
  // @param records contains the matching records.
  void GetRecordsAt(Address addr, std::vector<RecordPtr>* records) const;

  // Gets records that fully span |range|.
  // @pre @p range must be a valid.
  // @param range the address range the region records should span.
  // @param records contains the matching records.
  void GetRecordsSpanning(const AddressRange& range,
                          std::vector<RecordPtr>* records) const;

  // Gets records that intersect |range|.
  // @pre @p range must be a valid.
  // @param range the address range the region records should intersect.
  // @param records contains the matching records.
  void GetRecordsIntersecting(const AddressRange& range,
                              std::vector<RecordPtr>* records) const;

  // Removes |record| from the layer.
  // @param record the record to remove.
  // @returns true on success, false otherwise.
  bool RemoveRecord(const RecordPtr& record);

  // Iterators for range-based for loop.
  Iterator begin() { return Iterator(records_.begin()); }
  Iterator end() { return Iterator(records_.end()); }

  size_t size() const { return records_.size(); }

 private:
  std::multimap<Address, RecordPtr> records_;
};

template <typename RecordType>
class Iterator : public std::iterator<
    std::input_iterator_tag,
    typename ProcessState::Layer<RecordType>::RecordPtr> {
 public:
  typedef typename ProcessState::Layer<RecordType>::RecordPtr RecordPtr;

  Iterator() {}
  const RecordPtr& operator*() const { return it_->second; }
  Iterator& operator=(const Iterator&) {
    it_ = other.it_;
    return *this;
  }
  const Iterator& operator++() {
    ++it_;
    return *this;
  }
  bool operator==(const Iterator& other) const {
    return it_ == other.it_;
  }
  bool operator!=(const Iterator& other) const {
    return it_ != other.it_;
  }

 private:
  friend ProcessState::Layer<RecordType>;
  explicit Iterator(typename std::multimap<Address, RecordPtr>::iterator it)
      : it_(it) {}

  typename std::multimap<Address, RecordPtr>::iterator it_;
};

// ProcessState
template<typename RecordType>
bool ProcessState::FindLayer(scoped_refptr<Layer<RecordType>>* layer) {
  DCHECK(layer != nullptr);

  RecordId id = RecordTraits<RecordType>::ID;
  auto it = layers_.find(id);
  if (it != layers_.end()) {
    *layer = static_cast<Layer<RecordType>*>(it->second.get());
    return true;
  }

  return false;
}

template <typename RecordType>
void ProcessState::FindOrCreateLayer(
    scoped_refptr<Layer<RecordType>>* layer) {
  DCHECK(layer != nullptr);

  if (FindLayer(layer))
    return;

  CreateLayer(layer);
}

template<typename RecordType>
void ProcessState::CreateLayer(scoped_refptr<Layer<RecordType>>* layer) {
  DCHECK(layer != nullptr);

  scoped_refptr<Layer<RecordType>> new_layer = new Layer<RecordType>();
  DCHECK(new_layer.get() != nullptr);

  RecordId id = RecordTraits<RecordType>::ID;
  auto ib = layers_.insert(
      std::make_pair(id, scoped_refptr<LayerBase>(new_layer.get())));
  DCHECK(ib.second);

  layer->swap(new_layer);
}

// ProcessState::Layer
template <typename RecordType>
void ProcessState::Layer<RecordType>::CreateRecord(
    AddressRange range, RecordPtr* record) {
  DCHECK(range.IsValid());
  DCHECK(record != nullptr);

  RecordPtr new_record = new Record<RecordType>(range);
  records_.insert(std::make_pair(range.addr(), new_record));

  record->swap(new_record);
}

template <typename RecordType>
void ProcessState::Layer<RecordType>::GetRecordsAt(
    Address addr, std::vector<RecordPtr>* records) const {
  DCHECK(records != nullptr);

  records->clear();

  auto match = records_.equal_range(addr);
  for (auto it = match.first; it != match.second; ++it) {
    records->push_back(it->second);
  }
}

template <typename RecordType>
void ProcessState::Layer<RecordType>::GetRecordsSpanning(
    const AddressRange& range, std::vector<RecordPtr>* records) const {
  DCHECK(range.IsValid());
  DCHECK(records != nullptr);

  records->clear();

  for (const auto& entry : records_) {
    AddressRange record_range = entry.second->range();
    DCHECK(record_range.IsValid());
    if (record_range.Spans(range))
      records->push_back(entry.second);

    if (record_range.start() > range.start())
      // Records that start after the range, or any after, cannot span it.
      return;
  }
}

template <typename RecordType>
void ProcessState::Layer<RecordType>::GetRecordsIntersecting(
    const AddressRange& range, std::vector<RecordPtr>* records) const {
  DCHECK(range.IsValid());
  DCHECK(records != nullptr);

  records->clear();

  for (const auto& entry : records_) {
    AddressRange record_range = entry.second->range();
    DCHECK(record_range.IsValid());
    if (record_range.Intersects(range))
      records->push_back(entry.second);
  }
}

template <typename RecordType>
bool ProcessState::Layer<RecordType>::RemoveRecord(const RecordPtr& record) {
  DCHECK(record.get() != nullptr);

  // Note: a record can only appear once, as per API (CreateRecord is the only
  // mechanism to add a record).
  auto matches = records_.equal_range(record->range().addr());
  for (auto it = matches.first; it != matches.second; ++it) {
    if (it->second.get() == record.get()) {
      records_.erase(it);
      return true;
    }
  }

  return false;
}

}  // namespace refinery

#endif  // SYZYGY_REFINERY_PROCESS_STATE_PROCESS_STATE_H_
