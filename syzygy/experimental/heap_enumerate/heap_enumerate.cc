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
//
// Implements an experimental command line tool that allocates a heap, and
// makes some allocations in it, then dumps same to text through introspection
// with symbols.

#include "syzygy/experimental/heap_enumerate/heap_enumerate.h"

#include "base/logging.h"
#include "base/containers/hash_tables.h"
#include "base/strings/string16.h"
#include "base/strings/string_piece.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/core/bit_source.h"
#include "syzygy/refinery/types/dia_crawler.h"
#include "syzygy/refinery/types/type_repository.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/typed_data.h"

namespace {

using refinery::Address;
using refinery::AddressRange;
using refinery::ArrayTypePtr;
using refinery::BitSource;
using refinery::DiaCrawler;
using refinery::TypeRepository;
using refinery::TypePtr;
using refinery::TypedData;
using refinery::UserDefinedTypePtr;

bool GetFieldOffset(UserDefinedTypePtr record_type,
                    base::StringPiece16 field_name,
                    size_t* field_offset) {
  DCHECK(field_offset);
  for (auto f : record_type->fields()) {
    if (f.name() == field_name) {
      *field_offset = f.offset();
      return true;
    }
  }
  return false;
}

void Spaces(FILE* output, size_t indent) {
  for (size_t i = 0; i < indent; ++i)
    std::fputc(' ', output);
}

class TestBitSource : public BitSource {
 public:
  using AddressRange = AddressRange;

  ~TestBitSource() override {}

  bool GetAll(const AddressRange& range, void* data_ptr) override {
    DCHECK(range.IsValid());
    DCHECK(data_ptr);

    size_t read_bytes = 0;
    if (!GetFrom(range, &read_bytes, data_ptr))
      return false;
    if (read_bytes != range.size())
      return false;

    return true;
  }

  bool GetFrom(const AddressRange& range,
               size_t* data_cnt,
               void* data_ptr) override {
    DCHECK(range.IsValid());
    DCHECK(data_cnt);
    DCHECK(data_ptr);

    *data_cnt = 0;

    DWORD read_bytes = 0;
    BOOL succeeded = ::ReadProcessMemory(
        ::GetCurrentProcess(), reinterpret_cast<const void*>(range.addr()),
        data_ptr, range.size(), &read_bytes);
    if (!succeeded)
      return false;
    *data_cnt = read_bytes;

    return read_bytes != 0;
  }

  bool HasSome(const AddressRange& range) override {
    // TODO(siggi): Fixme!
    return true;
  }
};

class ListEntryEnumerator {
 public:
  ListEntryEnumerator();

  // Initialize the enumerator to walk entries of type @p record_type on the
  // field named @p list_entry_name from @p list_head.
  // @returns true on success, false on failure.
  bool Initialize(TypedData list_head,
                  UserDefinedTypePtr record_type,
                  base::StringPiece16 list_entry_name);

  // Advance to the next entry if possible.
  // @returns true on success, false on failure.
  bool Next();

  // The current entry, valid after a successful call to Next().
  const TypedData& current_record() const { return current_record_; }

 private:
  // Address of the list head.
  Address list_head_;
  // The offset of the the field named @p list_entry_name_ in @p record_type_.
  // Used to locate the start of the containing record, similar to
  // the CONTAINING_RECORD macro.
  size_t list_entry_offset_;
  // The name of the list entry field we're walking.
  base::string16 list_entry_name_;
  // The type of the record.
  UserDefinedTypePtr record_type_;
  // The current list entry. After Initialize this is the list head, after that
  // it's embedded in @p current_record_.
  TypedData current_list_entry_;
  // The current record, if any.
  TypedData current_record_;
};

ListEntryEnumerator::ListEntryEnumerator()
    : list_head_(0), list_entry_offset_(0) {
}

bool ListEntryEnumerator::Initialize(TypedData list_head,
                                     UserDefinedTypePtr record_type,
                                     base::StringPiece16 list_entry_name) {
  // Check that the list_head has an Flink.
  TypedData flink;
  if (!list_head.GetNamedField(L"Flink", &flink) || !flink.IsPointerType())
    return false;

  if (!GetFieldOffset(record_type, list_entry_name, &list_entry_offset_))
    return false;
  record_type_ = record_type;
  list_entry_name.CopyToString(&list_entry_name_);
  list_head_ = list_head.range().addr();
  current_list_entry_ = list_head;

  return true;
}

bool ListEntryEnumerator::Next() {
  TypedData flink;
  if (!current_list_entry_.GetNamedField(L"Flink", &flink))
    return false;

  Address flink_addr = 0;
  if (!flink.GetPointerValue(&flink_addr))
    return false;

  // Terminate on pointer back to the head.
  if (flink_addr == list_head_)
    return false;

  // Retrieve the next entry.
  TypedData next_entry(
      current_list_entry_.bit_source(), record_type_,
      AddressRange(flink_addr - list_entry_offset_, record_type_->size()));

  if (!next_entry.GetNamedField(list_entry_name_, &current_list_entry_))
    return false;
  current_record_ = next_entry;

  return true;
}

class HeapEnumerator {
 public:
  HeapEnumerator();

  bool Initialize(HANDLE heap, TypeRepository* repo);

  ListEntryEnumerator GetSegmentEnumerator();

 private:
  // A reflective bit source.
  TestBitSource bit_source_;

  // The heap we're enumerating.
  TypedData heap_;

  // The type for the _HEAP structure.
  UserDefinedTypePtr heap_type_;

  // Each heap is comprised of one or more segments - the _HEAP structure is
  // the first segment of the heap.
  UserDefinedTypePtr heap_segment_type_;

  // Each segment has zero or more uncommitted ranges, which are a run of
  // pages of uncommitted (or decommitted) memory. They are described by this
  // type.
  UserDefinedTypePtr heap_ucr_descriptor_type_;

  // Each segment is a concatenation of _HEAP_ENTRYs. Each heap entry has:
  // # a size, expressed in N*sizeof(_HEAP_ENTRY), the entry itself inclusive,
  // # some flags,
  // # a single-byte checksum, which is the XOR of the previous three bytes.
  // # The size of the previous entry, expressed in N*sizeof(_HEAP_ENTRY),
  // # The number of unused bytes in the entry.
  // Heap entries appear to coalesce with their free adjoining neighbors on
  // free, and presumably there are heuristics for when to uncommit all or some
  // of a free heap entry that spans multiple pages.
  UserDefinedTypePtr heap_entry_type_;

  // TODO(siggi): Figure out the purpose of this type.
  UserDefinedTypePtr heap_list_lookup_type_;

  // When a _HEAP has a FrontEndHeap of type "2", it's an _LFH_HEAP.
  // A low-fragmentation heap allocates "bins" from the backend _HEAP, and
  // breaks the bins down into equal-size user allocations.
  // Each LFH bin starts with a _HEAP_USERDATA_HEADER, and is then a
  // concatenation of _HEAP_ENTRYs.
  UserDefinedTypePtr lfh_heap_type_;

  // Each LFH bin starts with one of these.
  UserDefinedTypePtr heap_userdata_header_type_;
};

HeapEnumerator::HeapEnumerator() {
}

bool HeapEnumerator::Initialize(HANDLE heap, TypeRepository* repo) {
  DCHECK(heap);
  DCHECK(repo);

  // The types used to parse the heap.
  base::hash_map<base::string16, UserDefinedTypePtr*> wanted_udts;
  wanted_udts.insert(std::make_pair(L"_HEAP", &heap_type_));
  wanted_udts.insert(std::make_pair(L"_HEAP_SEGMENT", &heap_segment_type_));
  wanted_udts.insert(
      std::make_pair(L"_HEAP_UCR_DESCRIPTOR", &heap_ucr_descriptor_type_));
  wanted_udts.insert(std::make_pair(L"_HEAP_ENTRY", &heap_entry_type_));
  wanted_udts.insert(
      std::make_pair(L"_HEAP_LIST_LOOKUP", &heap_list_lookup_type_));
  wanted_udts.insert(std::make_pair(L"_LFH_HEAP", &lfh_heap_type_));
  wanted_udts.insert(
      std::make_pair(L"_HEAP_USERDATA_HEADER", &heap_userdata_header_type_));

  for (auto type : *repo) {
    auto it = wanted_udts.find(type->name());
    if (it != wanted_udts.end()) {
      // All these types should be unique, and if they're not, we pick the
      // first one.
      // TODO(siggi): Consider barfing on symbol duplication once we switch
      //     to the PdbCrawler as a symbol source.
      if (!type->CastTo(it->second))
        return false;

      wanted_udts.erase(it);
      if (wanted_udts.empty())
        break;
    }
  }

  if (!wanted_udts.empty()) {
    // TODO(siggi): Validate that all required types have been found, and that
    //    the optional types are consistent.
    return false;
  }

  heap_ = TypedData(
      &bit_source_, heap_type_,
      AddressRange(reinterpret_cast<Address>(heap), heap_type_->size()));

  return true;
}

ListEntryEnumerator HeapEnumerator::GetSegmentEnumerator() {
  TypedData segment_list;
  if (!heap_.GetNamedField(L"SegmentList", &segment_list)) {
    LOG(ERROR) << "No SegmentList in heap.";
    return ListEntryEnumerator();
  }

  ListEntryEnumerator heap_segment_enum;
  if (!heap_segment_enum.Initialize(segment_list, heap_segment_type_,
                                    L"SegmentListEntry")) {
    LOG(ERROR) << "Failed to initialize Segment enumerator";
    return ListEntryEnumerator();
  }

  return heap_segment_enum;
}

bool GetNtdllTypes(TypeRepository* repo) {
  HMODULE ntdll = ::GetModuleHandle(L"ntdll.dll");
  if (ntdll == nullptr)
    return false;

  wchar_t ntdll_path[MAX_PATH] = L"";
  if (!::GetModuleFileName(ntdll, ntdll_path, arraysize(ntdll_path)))
    return false;

  DiaCrawler crawler;
  if (!crawler.InitializeForFile(base::FilePath(ntdll_path)) ||
      !crawler.GetTypes(repo)) {
    return false;
  }

  return true;
}

}  // namespace

HeapEnumerate::HeapEnumerate() : heap_(nullptr), output_(nullptr) {
}

HeapEnumerate::~HeapEnumerate() {
  if (heap_ != nullptr) {
    BOOL destroyed = ::HeapDestroy(heap_);
    DCHECK(destroyed);
  }
}

bool HeapEnumerate::Initialize() {
  heap_ = ::HeapCreate(0, 0, 0);
  if (heap_ == nullptr)
    return false;

  return AllocateSomeBlocks();
}

bool HeapEnumerate::AllocateSomeBlocks() {
  // Allocate a bunch of memory for giggles.
  for (size_t i = 0; i < 30000; ++i) {
    const size_t kAllocSize = 513;
    void* alloc = ::HeapAlloc(heap_, 0, kAllocSize);
    if (alloc == nullptr)
      return false;
    ::memset(alloc, 0xFE, kAllocSize);
    allocs_.insert(
        std::make_pair(reinterpret_cast<Address>(alloc), kAllocSize));
  }

  return true;
}

void HeapEnumerate::DumpTypedData(TypedData data, size_t indent) {
  std::fprintf(output_, "%ls", data.type()->name().c_str());
  if (data.IsPointerType()) {
    Address addr = 0;
    data.GetPointerValue(&addr);
    std::fprintf(output_, "->0x%08llX\n", addr);
  } else if (data.IsPrimitiveType()) {
    uint64_t value = 0;
    if (data.GetUnsignedValue(&value)) {
      switch (data.type()->size()) {
        case sizeof(uint8_t):
          std::fprintf(output_, ": 0x%02llX\n", value);
          break;
        case sizeof(uint16_t):
          std::fprintf(output_, ": 0x%04llX\n", value);
          break;
        case sizeof(uint32_t):
          std::fprintf(output_, ": 0x%08llX\n", value);
          break;
        case sizeof(uint64_t):
          std::fprintf(output_, ": 0x%016llX\n", value);
          break;
        default:
          NOTREACHED();
          break;
      }
    } else {
      std::fprintf(output_, "*UNKNOWN*\n");
    }
  } else if (data.IsArrayType()) {
    ArrayTypePtr array;
    if (data.type()->CastTo(&array)) {
      std::fprintf(output_, "\n");
      size_t num_elements = array->num_elements();
      for (size_t i = 0; i < num_elements; ++i) {
        Spaces(output_, indent);
        std::fprintf(output_, "[%d]: ", i);
        TypedData element;
        data.GetArrayElement(i, &element);
        DumpTypedData(element, indent + 1);
      }
    }
  } else {
    UserDefinedTypePtr udt;
    if (data.type()->CastTo(&udt)) {
      std::fprintf(output_, "@0x%08llX:\n", data.range().addr());
      for (auto f : udt->fields()) {
        Spaces(output_, indent);

        TypePtr field_type = udt->repository()->GetType(f.type_id());
        TypedData field;
        data.GetField(f, &field);
        std::fprintf(output_, "(+0x%02X) %ls:", f.offset(), f.name().c_str());
        DumpTypedData(field, indent + 1);
      }
    } else {
      std::fprintf(output_, "*UNKNOWN*\n");
    }
  }
}

void HeapEnumerate::EnumerateHeap(FILE* output_file) {
  DCHECK(output_file);
  output_ = output_file;

  if (!Initialize())
    return;

  TypeRepository repo;
  if (!GetNtdllTypes(&repo))
    return;

  HeapEnumerator enumerator;
  if (!enumerator.Initialize(heap_, &repo))
    return;

  auto enum_segments = enumerator.GetSegmentEnumerator();
  while (enum_segments.Next()) {
    TypedData segment = enum_segments.current_record();

    DumpTypedData(segment, 0);
  }
}
