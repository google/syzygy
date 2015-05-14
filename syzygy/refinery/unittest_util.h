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

#ifndef SYZYGY_REFINERY_UNITTEST_UTIL_H_
#define SYZYGY_REFINERY_UNITTEST_UTIL_H_

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/strings/string_piece.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/process_state/process_state.h"

namespace testing {

class TestMinidumps {
 public:
  // @returns the path to a 32 bit notepad dump file.
  static const base::FilePath GetNotepad32Dump();
  // @returns the path to a 64 bit notepad dump file.
  static const base::FilePath GetNotepad64Dump();
};

// A MinidumpSpecification is used to describe and generate synthetic minidumps.
// If the specification is serialized, the generated minidump is erased as the
// specification is deleted.
class MinidumpSpecification {
 public:
  MinidumpSpecification();

  // Adds thread data to the specification. Note that the stack's memory must
  // be added independently to the specification. The adbsence of a memory
  // region spanning the stack's range leads to failure at serialization time.
  // @pre @p thread_size_bytes must be of size sizeof(MINIDUMP_THREAD).
  // @pre @p context_size_bytes must be of size sizeof(CONTEXT).
  // @param thread_data the address of the thread data to add.
  // @param thread_size_bytes the size of the thread data to add.
  // @param context_data the address of the context data to add.
  // @param context_size_bytes the size of the context data to add.
  // @returns true on success, false otherwise.
  bool AddThread(const void* thread_data,
                 size_t thread_size_bytes,
                 const void* context_data,
                 size_t context_size_bytes);

  // Adds a memory region to the specification.
  // @param addr the address the region is located at.
  // @param bytes the bytes that make up the region.
  // @returns true on success, false if the memory region is not valid or if it
  //   overlaps with an existing memory region.
  bool AddMemoryRegion(refinery::Address addr, base::StringPiece bytes);

  // Adds a memory region to the specification.
  // @param addr the address the region is located at.
  // @param data the address of the bytes that make up the region.
  // @param size_bytes the size of the region.
  // @returns true on success, false if the memory region is not valid or if it
  //   overlaps with an existing memory region.
  bool AddMemoryRegion(refinery::Address addr,
                       const void* data,
                       size_t size_bytes);

  // Serializes the specification.
  // @param dir the directory to serialize to.
  // @param path the path to the minidump.
  // @returns true on success, false otherwise.
  bool Serialize(const base::ScopedTempDir& dir, base::FilePath* path) const;

 private:
  // Represents thread and context.
  std::vector<std::pair<std::string, std::string>> threads_;
  std::map<refinery::Address, std::string> memory_regions_;

  DISALLOW_COPY_AND_ASSIGN(MinidumpSpecification);
};

}  // namespace testing

#endif  // SYZYGY_REFINERY_UNITTEST_UTIL_H_
