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
#include <string>
#include <vector>

#include "base/environment.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/containers/hash_tables.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string16.h"
#include "base/strings/string_piece.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/pe/find.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/core/bit_source.h"
#include "syzygy/refinery/testing/self_bit_source.h"
#include "syzygy/refinery/types/dia_crawler.h"
#include "syzygy/refinery/types/type_repository.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/typed_data.h"
#include "syzygy/experimental/heap_enumerate/heap_entry_walker.h"
#include "syzygy/experimental/heap_enumerate/list_entry_enumerator.h"

namespace {

using refinery::Address;
using refinery::AddressRange;
using refinery::ArrayTypePtr;
using refinery::BitSource;
using refinery::DiaCrawler;
using refinery::MemberFieldPtr;
using refinery::TypeRepository;
using refinery::TypePtr;
using refinery::TypedData;
using refinery::UserDefinedType;
using refinery::UserDefinedTypePtr;

// XORs the bytes in a memory range together and returns the result;
uint8_t xormem(const void* mem, size_t num_bytes) {
  const uint8_t* mem_ptr = reinterpret_cast<const uint8_t*>(mem);
  uint8_t ret = 0;
  for (size_t i = 0; i < num_bytes; ++i)
    ret ^= *mem_ptr++;

  return ret;
}

// TODO(siggi): Move somewhere central and eliminate dupes.
bool GetNamedValueUnsigned(const refinery::TypedData& data,
                           base::StringPiece16 field_name,
                           uint64_t* value) {
  DCHECK(value);
  refinery::TypedData field;
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

bool GetNtdllTypes(TypeRepository* repo) {
  // As of 28/10/2015 the symbol file for ntdll.dll on Win7 is missing the
  // crucial symbols for heap enumeration. This code deserves to either die
  // in a fire, or else be updated to find symbols that are close to the
  // system in version and bitness.
  pe::PEFile::Signature ntdll_sig(L"ntdll.dll", core::AbsoluteAddress(0),
                                  0x141000, 0, 0x560D708C);

  std::unique_ptr<base::Environment> env(base::Environment::Create());
  std::string search_path;
  if (!env->GetVar("_NT_SYMBOL_PATH", &search_path)) {
    // TODO(siggi): Set a default when it's missing.
    LOG(ERROR) << "Missing symbol path.";
    return false;
  }

  base::FilePath ntdll_path;
  if (!pe::FindModuleBySignature(ntdll_sig, base::UTF8ToUTF16(search_path),
                                 &ntdll_path)) {
    LOG(ERROR) << "Failed to locate NTDLL.";
    return false;
  }

  DiaCrawler crawler;
  if (!crawler.InitializeForFile(base::FilePath(ntdll_path)) ||
      !crawler.GetTypes(repo)) {
    LOG(ERROR) << "Failed to get ntdll types.";
    return false;
  }

  return true;
}

}  // namespace

class HeapEnumerate::HeapEnumerator {
 public:
  HeapEnumerator();

  bool Initialize(HANDLE heap, TypeRepository* repo);

  // Get an enumerator for the heap's segment list.
  ListEntryEnumerator GetSegmentEnumerator();

  // Get an enumerator for a segment's UCR list.
  ListEntryEnumerator GetUCREnumerator(const TypedData& segment);

  // Retrieves the front end heap - if enabled.
  bool GetFrontEndHeap(TypedData* front_end_heap);

  // Accessor to the heap.
  const TypedData& heap() const { return heap_; }

  UserDefinedTypePtr heap_userdata_header_type() const {
    return heap_userdata_header_type_;
  }
  BitSource* bit_source() const {
    return const_cast<testing::SelfBitSource*>(&bit_source_);
  }

 private:
  // A reflective bit source.
  testing::SelfBitSource bit_source_;

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

HeapEnumerate::HeapEnumerator::HeapEnumerator() {
}

bool HeapEnumerate::HeapEnumerator::Initialize(HANDLE heap,
                                               TypeRepository* repo) {
  DCHECK(heap);
  DCHECK(repo);

  // The types used to parse the heap.
  std::unordered_map<base::string16, UserDefinedTypePtr*> wanted_udts;
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
    auto it = wanted_udts.find(type->GetName());
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
    LOG(ERROR) << "Missing ntdll UDTs:";
    for (auto type : wanted_udts)
      LOG(ERROR) << "  " << type.first;

    LOG(ERROR) << "Available ntdll UDTs:";
    for (auto type : *repo)
      LOG(ERROR) << "  " << type->GetName();

    return false;
  }

  heap_ = TypedData(&bit_source_, heap_type_, reinterpret_cast<Address>(heap));

  return true;
}

ListEntryEnumerator HeapEnumerate::HeapEnumerator::GetSegmentEnumerator() {
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

ListEntryEnumerator HeapEnumerate::HeapEnumerator::GetUCREnumerator(
    const TypedData& segment) {
  TypedData ucr_list;
  if (!segment.GetNamedField(L"UCRSegmentList", &ucr_list)) {
    LOG(ERROR) << "No UCRSegmentList in segment.";
    return ListEntryEnumerator();
  }

  ListEntryEnumerator ucr_list_enum;
  if (!ucr_list_enum.Initialize(ucr_list, heap_ucr_descriptor_type_,
                                L"SegmentEntry")) {
    LOG(ERROR) << "Failed to initialize UCR enumerator";
    return ListEntryEnumerator();
  }

  return ucr_list_enum;
}

bool HeapEnumerate::HeapEnumerator::GetFrontEndHeap(TypedData* front_end_heap) {
  DCHECK(front_end_heap);
  uint64_t front_end_heap_type = 0;
  if (!GetNamedValueUnsigned(heap_, L"FrontEndHeapType", &front_end_heap_type))
    return false;

  // From looking at some heaps.
  const uint64_t kLFHHeapType = 2;
  if (front_end_heap_type != kLFHHeapType)
    return false;

  TypedData front_end_heap_field;
  Address front_end_heap_addr = 0;
  if (!heap_.GetNamedField(L"FrontEndHeap", &front_end_heap_field) ||
      !front_end_heap_field.GetPointerValue(&front_end_heap_addr)) {
    return false;
  }

  if (!lfh_heap_type_)
    return false;

  *front_end_heap =
      TypedData(heap_.bit_source(), lfh_heap_type_, front_end_heap_addr);
  return true;
}

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

void HeapEnumerate::DumpTypedData(const TypedData& data, size_t indent) {
  std::fprintf(output_, "%ls", data.type()->GetName().c_str());
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
      std::fprintf(output_, "@0x%08llX:\n", data.addr());

      // Print out members.
      const UserDefinedType::Fields& fields = udt->fields();
      for (size_t i = 0; i < fields.size(); ++i) {
        MemberFieldPtr member;
        if (!fields[i]->CastTo(&member))
          continue;
        Spaces(output_, indent);
        std::fprintf(output_, "(+0x%02X) %ls:", member->offset(),
                     member->name().c_str());

        TypedData member_data;
        if (!data.GetField(i, &member_data)) {
          std::fprintf(output_, "*failed to get member data*\n");
          continue;
        }
        DumpTypedData(member_data, indent + 1);
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

  scoped_refptr<TypeRepository> repo = new TypeRepository();
  if (!GetNtdllTypes(repo.get()))
    return;

  HeapEnumerator enumerator;
  if (!enumerator.Initialize(heap_, repo.get()))
    return;

  // Dump the heap structure itself.
  DumpTypedData(enumerator.heap(), 0);

  TypedData front_end_heap;
  if (enumerator.GetFrontEndHeap(&front_end_heap))
    DumpTypedData(front_end_heap, 0);

  // Enumerate the segments of the heap, by walking the segment list.
  ListEntryEnumerator enum_segments = enumerator.GetSegmentEnumerator();
  while (enum_segments.Next()) {
    TypedData segment = enum_segments.current_record();

    DumpTypedData(segment, 0);

    // This is used to walk the entries in each segment.
    SegmentEntryWalker segment_walker;
    // Enumerate the entries in the segment by walking them.
    if (segment_walker.Initialize(enumerator.bit_source(), enumerator.heap(),
                                  segment)) {
      EnumSegment(enumerator, &segment_walker);
    } else {
      LOG(ERROR) << "EnumSegment failed.";
    }

    ListEntryEnumerator enum_ucrs = enumerator.GetUCREnumerator(segment);
    while (enum_ucrs.Next())
      DumpTypedData(enum_ucrs.current_record(), 1);
  }
}

void HeapEnumerate::EnumSegment(const HeapEnumerator& enumerator,
                                SegmentEntryWalker* segment_walker) {
  uint16_t prev_size = 0;
  while (!segment_walker->AtEnd()) {
    SegmentEntryWalker::HeapEntry entry = {};
    if (!segment_walker->GetDecodedEntry(&entry)) {
      // TODO(siggi): This currently happens on stepping into an
      //     uncommitted range - do better - but how?
      fprintf(output_, "GetDecodedEntry failed @0x%08llX(%d)\n",
              segment_walker->curr_entry().addr(),
              segment_walker->curr_entry().type()->size());
      break;
    }

    uint8_t checksum = xormem(&entry, 3);
    if (checksum != entry.tag) {
      ::fprintf(output_, "Checksum failed. Expected 0x%08X, got 0x%08X\n",
                checksum, entry.tag);
    }

    // The address range covered by the current entry.
    refinery::AddressRange range(segment_walker->curr_entry().addr(),
                                 entry.size * sizeof(entry));
    ::fprintf(output_, "Entry@0x%08llX(%d)\n", range.start(), range.size());

    ::fprintf(output_, " size: 0x%04X\n", entry.size);
    ::fprintf(output_, " flags: 0x%02X\n", entry.flags);
    ::fprintf(output_, " tag: 0x%02X\n", entry.tag);
    bool mismatch = prev_size != entry.prev_size;
    ::fprintf(output_, " prev_size: 0x%04X%s\n", entry.prev_size,
              mismatch ? " **MISMATCH**" : "");
    prev_size = entry.size;
    ::fprintf(output_, " segment_index: 0x%02X\n", entry.segment_index);
    ::fprintf(output_, " unused_bytes: 0x%02X\n", entry.unused_bytes);

    // TODO(siggi): The name of this flag does not fit modern times?
    if (entry.flags & HEAP_ENTRY_VIRTUAL_ALLOC) {
      LFHBinWalker bin_walker;
      if (bin_walker.Initialize(
              enumerator.heap().addr(), enumerator.bit_source(),
              enumerator.heap_userdata_header_type(), segment_walker)) {
        EnumLFHBin(enumerator, &bin_walker);
      } else {
        fprintf(output_, "LFHBinWalker::Initialize failed\n");
      }
    } else {
      PrintAllocsInRange(range);
    }

    if (!segment_walker->Next()) {
      fprintf(output_, "Next failed\n");
      break;
    }
  }
}

void HeapEnumerate::EnumLFHBin(const HeapEnumerator& enumerator,
                               LFHBinWalker* bin_walker) {
  ::fprintf(output_, "  LFHKey: 0x%16llX\n", bin_walker->lfh_key());

  const TypedData& udh = bin_walker->heap_userdata_header();
  DumpTypedData(udh, 2);

  TypedData subsegment;
  TypedData heap_subsegment;
  if (udh.GetNamedField(L"SubSegment", &subsegment) &&
      subsegment.Dereference(&heap_subsegment)) {
    DumpTypedData(heap_subsegment, 2);
  }

  uint64_t signature = 0;
  if (GetNamedValueUnsigned(udh, L"Signature", &signature)) {
    const uint32_t kUDHMagic = 0xF0E0D0C0;
    if (signature != kUDHMagic) {
      // This seems to happen for the last entry in a segment.
      // TODO(siggi): figure this out for realz.
      ::fprintf(output_, "UDH signature incorrect: 0x%08llX\n", signature);
      return;
    }
  } else {
    ::fprintf(output_, "GetNamedValueUnsigned failed.\n");
    return;
  }

  while (!bin_walker->AtEnd()) {
    LFHBinWalker::LFHEntry entry = {};
    if (!bin_walker->GetDecodedEntry(&entry)) {
      fprintf(output_, "GetDecodedEntry failed @0x%08llX(%d)\n",
              bin_walker->curr_entry().addr(),
              bin_walker->curr_entry().type()->size());
      break;
    }
    refinery::AddressRange range(bin_walker->curr_entry().addr(),
                                 bin_walker->entry_byte_size());

    ::fprintf(output_, "LFHEntry@0x%08llX(%d)\n", range.start(), range.size());

    // TODO(siggi): Validate that each entry points to the same
    //     subsegment.
    ::fprintf(output_, " heap_subsegment: 0x%08X\n", entry.heap_subsegment);
    ::fprintf(output_, " prev_size: 0x%02X\n", entry.prev_size);
    ::fprintf(output_, " segment_index: 0x%02X\n", entry.segment_index);
    ::fprintf(output_, " unused_bytes: 0x%02X\n", entry.unused_bytes);

    // TODO(siggi): Validate that the alloc is contained in the
    //    entry.
    PrintAllocsInRange(range);

    if (!bin_walker->Next())
      break;
  }
}
