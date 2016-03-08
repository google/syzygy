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

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/strings/string_piece.h"
#include "gtest/gtest.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/process_state/process_state.h"

namespace testing {

// A MinidumpSpecification is used to describe and generate synthetic minidumps.
// If the specification is serialized, the generated minidump is erased as the
// specification is deleted.
class MinidumpSpecification {
 public:
  // Forward.
  struct MemorySpecification;
  struct ThreadSpecification;
  struct ExceptionSpecification;
  struct ModuleSpecification;

  enum AllowMemoryOverlap {
    ALLOW_MEMORY_OVERLAP,
  };

  MinidumpSpecification();
  explicit MinidumpSpecification(AllowMemoryOverlap dummy);

  // Adds thread data to the specification. Note that the stack's memory must
  // be added independently to the specification. The adbsence of a memory
  // region spanning the stack's range leads to failure at serialization time.
  // @pre @p thread.thread_data.size() must be sizeof(MINIDUMP_THREAD).
  // @pre @p thread.context_data.size() must be sizeof(CONTEXT).
  // @param thread the specification of the thread data to addd.
  // @returns true on success, false otherwise.
  // TODO(manzagop): worth avoiding the copy? Here and below.
  bool AddThread(const ThreadSpecification& thread);

  // Adds a memory region to the specification.
  // @param addr the memory specification to add.
  // @returns true on success, false if the memory region is not valid or if it
  //   overlaps with an existing memory region.
  bool AddMemoryRegion(const MemorySpecification& spec);

  // Adds a module to the specification.
  // @param module the specification of the module to add.
  // @returns true on success, false otherwise.
  bool AddModule(const ModuleSpecification& module);

  // Adds an exception to the specification.
  // @param module the specification of the exception to add.
  // @returns true on success, false otherwise.
  bool AddException(const ExceptionSpecification& exception);

  // Serializes the specification.
  // @param dir the directory to serialize to.
  // @param path the path to the minidump.
  // @returns true on success, false otherwise.
  bool Serialize(const base::ScopedTempDir& dir, base::FilePath* path) const;

 private:
  std::vector<ThreadSpecification> threads_;  // Represents thread and context.
  std::vector<MemorySpecification> memory_regions_;
  std::vector<ModuleSpecification> modules_;
  std::vector<ExceptionSpecification> exceptions_;

  bool allow_memory_overlap_;
  std::map<refinery::Address, refinery::Size> region_sizes_;

  DISALLOW_COPY_AND_ASSIGN(MinidumpSpecification);
};

class SyntheticMinidumpTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  }

  void Serialize(const MinidumpSpecification& spec) {
    ASSERT_TRUE(spec.Serialize(temp_dir_, &dump_file_));
  }

  const base::FilePath& dump_file() const { return dump_file_; }

 private:
  base::ScopedTempDir temp_dir_;
  base::FilePath dump_file_;
};

struct MinidumpSpecification::MemorySpecification {
  MemorySpecification();
  MemorySpecification(refinery::Address addr, base::StringPiece data);

  refinery::Address address;
  std::string buffer;
};

struct MinidumpSpecification::ThreadSpecification {
  // Constructor that initializes the specification using provided parameters.
  // @param thread_id the id of the thread.
  // @param stack_address the address id of the thread's stack.
  // @param stack_size the size of the thread's stack.
  ThreadSpecification(size_t thread_id,
                      refinery::Address stack_address,
                      refinery::Size stack_size);

  void SetTebAddress(refinery::Address addr);

  // Sets @p spec to a memory specification that is suitable for backing with
  // the current specification's stack.
  // @param spec the memory specification to set.
  void FillStackMemorySpecification(
      MinidumpSpecification::MemorySpecification* spec) const;

  std::string thread_data;  // represents a MINIDUMP_THREAD.
  std::string context_data;  // represents a CONTEXT.
};

struct MinidumpSpecification::ExceptionSpecification {
  explicit ExceptionSpecification(uint32_t thread_id);

  uint32_t thread_id;
  uint32_t exception_code;
  uint32_t exception_flags;
  uint64_t exception_record;
  uint64_t exception_address;
  std::vector<uint64_t> exception_information;

  std::string context_data;  // represents a CONTEXT.
};

struct MinidumpSpecification::ModuleSpecification {
  ModuleSpecification();

  refinery::Address addr;
  refinery::Size size;
  uint32_t checksum;
  uint32_t timestamp;
  std::string name;
};

// Allows grabbing a minidump of our own process.
class ScopedMinidump {
 public:
  // Minidump with stacks, but no referenced data.
  static const uint32_t kMinidumpWithStacks;
  // Minidump with stacks and referenced data.
  static const uint32_t kMinidumpWithData;

  ScopedMinidump() = default;

  bool GenerateMinidump(uint32_t minidump_type);

  base::FilePath temp_dir() { return temp_dir_.path(); }
  base::FilePath minidump_path() { return minidump_path_; }

 private:
  base::ScopedTempDir temp_dir_;
  base::FilePath minidump_path_;

  DISALLOW_COPY_AND_ASSIGN(ScopedMinidump);
};

// Wraps a Windows heap for testing purposes.
class ScopedHeap {
 public:
  ScopedHeap();
  ~ScopedHeap();

  bool Create();

  void* Allocate(size_t block_size);
  bool Free(void* block);

  bool IsLFHBlock(const void* ptr);

 private:
  HANDLE heap_;

  DISALLOW_COPY_AND_ASSIGN(ScopedHeap);
};

// Casts a pointer to an address.
refinery::Address ToAddress(const void* ptr);

// Tests for the presence of appverifier.
bool IsAppVerifierActive();

}  // namespace testing

#endif  // SYZYGY_REFINERY_UNITTEST_UTIL_H_
