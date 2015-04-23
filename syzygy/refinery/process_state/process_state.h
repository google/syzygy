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

#include <stdint.h>
#include <map>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "syzygy/refinery/process_state/record_traits.h"

namespace refinery {

// TODO(siggi): Move this somewhere more central.
typedef uint64_t Address;
typedef uint32_t Size;

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
  ~LayerBase() {}

  DISALLOW_COPY_AND_ASSIGN(LayerBase);
};

// An individual record of a layer. Contains the data associated with the
// record as a protobuffer.
template <typename RecordType>
class ProcessState::Record : public base::RefCounted<Record<RecordType>> {
 public:
  Record(Address addr, Size size) : addr_(addr), size_(size) {}

  // @name Accessors.
  // @{
  Address addr() const { return addr_; }
  Size size() const { return size_; }
  RecordType* mutable_data() { return &data_; }
  const RecordType& data() { return data_; }
  // @}

 private:
  friend class base::RefCounted<Record<RecordType>>;
  ~Record() {}

  Address addr_;
  Size size_;
  RecordType data_;

  DISALLOW_COPY_AND_ASSIGN(Record);
};

template <typename RecordType>
class ProcessState::Layer : public ProcessState::LayerBase {
 public:
  typedef scoped_refptr<Record<RecordType>> RecordPtr;

  void CreateRecord(Address add, Size size, RecordPtr* record);

 private:
  std::map<Record<RecordType>*, RecordPtr> records_;
};

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

template <typename RecordType>
void ProcessState::Layer<RecordType>::CreateRecord(
    Address addr, Size size, RecordPtr* record) {
  DCHECK(record != nullptr);
  RecordPtr new_record = new Record<RecordType>(addr, size);

  auto ib = records_.insert(std::make_pair(new_record.get(), new_record));
  DCHECK(ib.second);

  record->swap(new_record);
}

}  // namespace refinery

#endif  // SYZYGY_REFINERY_PROCESS_STATE_PROCESS_STATE_H_
