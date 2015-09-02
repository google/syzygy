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

#include <algorithm>

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

// XORs a memory range into another memory range.
void memxor(void* dst, const void* src, size_t num_bytes) {
  uint8_t* dst_ptr = reinterpret_cast<uint8_t*>(dst);
  const uint8_t* src_ptr = reinterpret_cast<const uint8_t*>(src);

  for (size_t i = 0; i < num_bytes; ++i)
    *dst_ptr++ ^= *src_ptr++;
}

// XORs the bytes in a memory range together and returns the result;
uint8_t xormem(const void* mem, size_t num_bytes) {
  const uint8_t* mem_ptr = reinterpret_cast<const uint8_t*>(mem);
  uint8_t ret = 0;
  for (size_t i = 0; i < num_bytes; ++i)
    ret ^= *mem_ptr++;

  return ret;
}

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

bool GetNamedValueUnsigned(const TypedData& data,
                           base::StringPiece16 field_name,
                           uint64* value) {
  DCHECK(value);
  TypedData field;
  if (!data.GetNamedField(field_name, &field) ||
      !field.GetUnsignedValue(value)) {
    return false;
  }

  return true;
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

  // Accessor to the heap.
  TypedData heap() const { return heap_; }

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

// TODO(siggi): This thing needs two modes for de-obfuscating heap entries.
//   The Heap mode XORs the "Encoding" field into the HEAP_ENTRY, given the
//   "EncodeFlagMask" value is just so. This is the mode used when walking
//   heap segments.
//   The LFH mode mixes an ntdll local variable, with the HEAP pointer/handle
//   with the address of the entry for obfuscation.
class HeapEntryWalker {
 public:
  struct HeapEntry {
    uint16_t size;
    uint8_t flags;
    uint8_t tag;
    uint16_t prev_size;
    uint8_t segment_index;  // TODO(siggi): is this right???
    uint8_t unused_bytes;
  };
  COMPILE_ASSERT(sizeof(HeapEntry) == 8, heap_entry_is_not_8_bytes);

  HeapEntryWalker();

  // Initialize the walker.
  bool Initialize(HeapEnumerator* heap_enumerator);

  // Prepare to walk @p segment.
  bool EnumSegment(const TypedData& segment);

  // Returns the current entry decoded.
  bool GetDecodedEntry(HeapEntry* entry);

  // Returns true iff the current entry is at or past the segment range.
  bool AtEnd() const;

  // Walk to the next entry in the segment.
  bool Next();

  // Accessor.
  const TypedData& curr_entry() const { return curr_entry_; }

 private:
  // A bit source that covers all memory we have for the heap.
  BitSource* heap_bit_source_;

  // An address range covering the segment under enumeration.
  AddressRange segment_range_;

  // The current heap entry.
  TypedData curr_entry_;

  // The encoding for entries in this range.
  // TODO(siggi): This needs to change for LFH entry walking.
  std::vector<uint8_t> encoding_;
};

HeapEntryWalker::HeapEntryWalker() : heap_bit_source_(nullptr) {
}

bool HeapEntryWalker::Initialize(HeapEnumerator* heap_enumerator) {
  DCHECK(heap_enumerator);

  // Three ways to get through here:
  // 1. The heap doesn't know of encoding or encode flags mask.
  // 2. The heap doesn't have encoding enabled.
  // 3. The heap has encoding enabled.
  // Only in the third case is the encoding_ vector initialized.
  TypedData encode_flag_mask;
  TypedData encoding;
  TypedData heap = heap_enumerator->heap();
  bool has_flags = heap.GetNamedField(L"EncodeFlagMask", &encode_flag_mask);
  bool has_encoding = heap.GetNamedField(L"Encoding", &encoding);
  if (has_flags != has_encoding) {
    LOG(ERROR) << "Strangeness in types: "
               << "only one of Encoding and EncodeFlagMask present!";
    return false;
  }
  if (!has_flags)
    return true;

  uint64 value = 0;
  if (!encode_flag_mask.GetUnsignedValue(&value)) {
    LOG(ERROR) << "Unable to get heap flags mask.";
    return false;
  }
  // From observation of some heaps.
  const uint64 kEncodingEnabled = 0x00100000;
  if (value & kEncodingEnabled) {
    BitSource* source = encoding.bit_source();
    encoding_.resize(encoding.range().size());
    if (!source->GetAll(encoding.range(), &encoding_.at(0)))
      return false;
  }

  heap_bit_source_ = heap.bit_source();

  return true;
}

bool HeapEntryWalker::EnumSegment(const TypedData& segment) {
  // Get the first entry.
  if (!segment.GetNamedField(L"Entry", &curr_entry_))
    return false;

  // Get the end address of the mapped part of the segment.
  uint64_t last_valid_entry = 0;
  if (!GetNamedValueUnsigned(segment, L"LastValidEntry", &last_valid_entry))
    return false;

  // Note that the segment can be discontiguous if it contains any uncommitted
  // ranges. Uncommitted ranges are stored as a list of whole pages with
  // _HEAP_UCR_DESCRIPTOR structures.
  segment_range_ =
      AddressRange(segment.range().addr(),
                   Address(last_valid_entry) - segment.range().addr());

  return true;
}

bool HeapEntryWalker::GetDecodedEntry(HeapEntry* entry) {
  DCHECK(entry);
  HeapEntry tmp = {};

  // Bail if the current entry is for some reason not of the right size.
  if (curr_entry_.range().size() != sizeof(tmp))
    return false;

  // Get the raw entry.
  if (!heap_bit_source_->GetAll(curr_entry_.range(), &tmp))
    return false;

  // Unencode it.
  if (encoding_.size() == sizeof(tmp))
    memxor(&tmp, &encoding_.at(0), sizeof(tmp));

  *entry = tmp;

  return true;
}

bool HeapEntryWalker::AtEnd() const {
  if (curr_entry_.range().end() >= segment_range_.end())
    return true;

  return false;
}

bool HeapEntryWalker::Next() {
  HeapEntry curr_entry = {};
  if (!GetDecodedEntry(&curr_entry))
    return false;

  TypePtr entry_type = curr_entry_.type();
  Address next_start_addr =
      curr_entry_.range().start() + entry_type->size() * curr_entry.size;

  // TODO(siggi): Verify that this is monotonically forward...
  curr_entry_ = TypedData(heap_bit_source_, entry_type,
                          AddressRange(next_start_addr, entry_type->size()));

  return true;
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

void HeapEnumerate::PrintAllocsInRange(const refinery::AddressRange& range) {
  auto it = allocs_.lower_bound(range.start());

  for (; it != allocs_.end() && it->first <= range.end(); ++it)
    ::fprintf(output_, "  Alloc@0x%08llX(%d)\n", it->first, it->second);
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

  // This is used to walk the entries in each segment.
  HeapEntryWalker walker;
  if (!walker.Initialize(&enumerator))
    return;

  // Enumerate the segments of the heap, by walking the segment list.
  ListEntryEnumerator enum_segments = enumerator.GetSegmentEnumerator();
  while (enum_segments.Next()) {
    TypedData segment = enum_segments.current_record();

    DumpTypedData(segment, 0);

    // Enumerate the entries in the segment by walking them.
    if (walker.EnumSegment(segment)) {
      uint16_t prev_size = 0;

      while (!walker.AtEnd()) {
        HeapEntryWalker::HeapEntry entry = {};
        if (!walker.GetDecodedEntry(&entry)) {
          // TODO(siggi): This currently happens on stepping into an
          //     uncommitted range - do better - but how?
          fprintf(output_, "GetDecodedEntry failed\n");
          break;
        }

        uint8_t checksum = xormem(&entry, 3);
        if (checksum != entry.tag) {
          ::fprintf(output_, "Checksum failed. Expected 0x%08X, got 0x%08X\n",
                    checksum, entry.tag);
        }

        // The address range covered by the current entry.
        refinery::AddressRange range(walker.curr_entry().range().addr(),
                                     entry.size * sizeof(entry));
        ::fprintf(output_, "Entry@0x%08llX(%d)\n", range.addr(), range.size());

        ::fprintf(output_, " size: 0x%04X\n", entry.size);
        ::fprintf(output_, " flags: 0x%02X\n", entry.flags);
        ::fprintf(output_, " tag: 0x%02X\n", entry.tag);
        bool mismatch = prev_size != entry.prev_size;
        ::fprintf(output_, " prev_size: 0x%04X%s\n", entry.prev_size,
                  mismatch ? " **MISMATCH**" : "");
        prev_size = entry.size;
        ::fprintf(output_, " segment_index: 0x%02X\n", entry.segment_index);
        ::fprintf(output_, " unused_bytes: 0x%02X\n", entry.unused_bytes);
        PrintAllocsInRange(range);

        if (!walker.Next()) {
          fprintf(output_, "Next failed\n");
          break;
        }
      }
    } else {
      LOG(ERROR) << "EnumSegment failed.";
    }
  }
}
