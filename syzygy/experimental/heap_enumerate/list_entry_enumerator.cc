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

#include "syzygy/experimental/heap_enumerate/list_entry_enumerator.h"

namespace {

bool GetMemberFieldOffset(refinery::UserDefinedTypePtr record_type,
                    base::StringPiece16 field_name,
                    size_t* field_offset) {
  DCHECK(field_offset);
  for (auto f : record_type->fields()) {
    refinery::MemberFieldPtr member;
    if (!f->CastTo(&member))
      continue;

    if (member->name() == field_name) {
      *field_offset = member->offset();
      return true;
    }
  }
  return false;
}

}  // namespace

ListEntryEnumerator::ListEntryEnumerator()
    : list_head_(0), list_entry_offset_(0) {
}

bool ListEntryEnumerator::Initialize(const refinery::TypedData& list_head,
                                     refinery::UserDefinedTypePtr record_type,
                                     base::StringPiece16 list_entry_name) {
  // Check that the list_head has an Flink.
  refinery::TypedData flink;
  if (!list_head.GetNamedField(L"Flink", &flink) || !flink.IsPointerType())
    return false;

  if (!GetMemberFieldOffset(record_type, list_entry_name, &list_entry_offset_))
    return false;
  record_type_ = record_type;
  list_entry_name.CopyToString(&list_entry_name_);
  list_head_ = list_head.addr();
  current_list_entry_ = list_head;

  return true;
}

bool ListEntryEnumerator::Next() {
  refinery::TypedData flink;
  if (!current_list_entry_.GetNamedField(L"Flink", &flink))
    return false;

  refinery::Address flink_addr = 0;
  if (!flink.GetPointerValue(&flink_addr))
    return false;

  // Terminate on pointer back to the head.
  if (flink_addr == list_head_)
    return false;

  // Retrieve the next entry.
  refinery::TypedData next_entry(current_list_entry_.bit_source(),
                                 record_type_,
                                 flink_addr - list_entry_offset_);

  if (!next_entry.GetNamedField(list_entry_name_, &current_list_entry_))
    return false;
  current_record_ = next_entry;

  return true;
}
