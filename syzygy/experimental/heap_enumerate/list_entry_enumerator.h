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

#ifndef SYZYGY_EXPERIMENTAL_HEAP_ENUMERATE_LIST_ENTRY_ENUMERATOR_H_
#define SYZYGY_EXPERIMENTAL_HEAP_ENUMERATE_LIST_ENTRY_ENUMERATOR_H_

#include "base/strings/string_piece.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/typed_data.h"

// A class to implement generic walking records chained together in
// double-linked _LIST_ENTRY lists.
class ListEntryEnumerator {
 public:
  ListEntryEnumerator();

  // Initialize the enumerator to walk entries of type @p record_type on the
  // field named @p list_entry_name from @p list_head.
  // @param list_head the list head to walk from.
  // @param record_type the type of record to walk. Note that @p record_type
  //     must contain a field of type (or compatible with) _LIST_ENTRY.
  // @returns true on success, false on failure.
  bool Initialize(const refinery::TypedData& list_head,
                  refinery::UserDefinedTypePtr record_type,
                  base::StringPiece16 list_entry_name);

  // Advance to the next entry if possible.
  // @returns true on success, false on failure.
  bool Next();

  // The current entry, valid after a successful call to Next().
  const refinery::TypedData& current_record() const { return current_record_; }

 private:
  // Address of the list head.
  refinery::Address list_head_;
  // The offset of the the field named @p list_entry_name_ in @p record_type_.
  // Used to locate the start of the containing record, similar to
  // the CONTAINING_RECORD macro.
  size_t list_entry_offset_;
  // The name of the list entry field we're walking.
  base::string16 list_entry_name_;
  // The type of the record.
  refinery::UserDefinedTypePtr record_type_;
  // The current list entry. After Initialize this is the list head, after that
  // it's embedded in @p current_record_.
  refinery::TypedData current_list_entry_;
  // The current record, if any.
  refinery::TypedData current_record_;
};

#endif  // SYZYGY_EXPERIMENTAL_HEAP_ENUMERATE_LIST_ENTRY_ENUMERATOR_H_
