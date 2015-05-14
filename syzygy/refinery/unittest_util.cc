// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/refinery/unittest_util.h"

#include <windows.h>  // NOLINT
#include <dbghelp.h>

#include <cstring>
#include <vector>

#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/numerics/safe_math.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace testing {

const base::FilePath TestMinidumps::GetNotepad32Dump() {
  return GetSrcRelativePath(L"syzygy\\refinery\\test_data\\notepad-32bit.dmp");
}

const base::FilePath TestMinidumps::GetNotepad64Dump() {
  return GetSrcRelativePath(L"syzygy\\refinery\\test_data\\notepad-64bit.dmp");
}

namespace {

// TODO(manzagop): ensure on destruction or finalizing that the allocations are
// actually reflected in the file. At this point, allocating without writing
// would leave the file short.
class MinidumpSerializer {
 public:
  typedef RVA Position;

  MinidumpSerializer();

  // @pre @p dir must be a valid directory.
  bool Initialize(const base::ScopedTempDir& dir);
  bool SerializeThreads(
      const std::vector<std::pair<std::string, std::string>>& threads);
  bool SerializeMemory(const std::map<refinery::Address, std::string>& regions);
  bool Finalize();

  const base::FilePath& path() const { return path_; }

 private:
  static const Position kHeaderPos = 0U;

  void SerializeDirectory();
  void SerializeHeader();

  Position Allocate(size_t size_bytes);

  // Allocate new space and write to it.
  template <class DataType>
  Position Append(const DataType& data);
  // @pre @p data must not be empty.
  template <class DataType>
  Position AppendVec(const std::vector<DataType>& data);
  // @pre @p elements must not be empty.
  template <class DataType>
  Position AppendStream(MINIDUMP_STREAM_TYPE type,
                        const std::vector<DataType>& elements);
  Position AppendBytes(base::StringPiece data);

  // Write to already allocated space.
  template <class DataType>
  void Write(Position pos, const DataType& data);
  void WriteBytes(Position pos, size_t size_bytes, const void* data);

  bool IncrementCursor(size_t size_bytes);

  // Gets the position of an address range which is fully contained in a
  // serialized range.
  // @pre is_serialize_memory_invoked_ must be true.
  // @param range the range for which to get the rva.
  // @param pos the returned position.
  // returns true on success, false otherwise.
  bool GetPos(const refinery::AddressRange& range, Position* pos) const;

  bool succeeded() const { return !failed_; }

  bool failed_;
  bool is_serialize_memory_invoked_;

  std::vector<MINIDUMP_DIRECTORY> directory_;

  Position cursor_;  // The next allocatable position.
  base::FilePath path_;
  base::ScopedFILE file_;

  std::map<refinery::AddressRange, Position> memory_positions_;
};

MinidumpSerializer::MinidumpSerializer()
    : failed_(true),
      is_serialize_memory_invoked_(false),
      cursor_(0U) {
}

bool MinidumpSerializer::Initialize(const base::ScopedTempDir& dir) {
  DCHECK(dir.IsValid());

  failed_ = false;
  is_serialize_memory_invoked_ = false;
  directory_.clear();

  // Create the backing file.
  cursor_ = 0U;
  if (!CreateTemporaryFileInDir(dir.path(), &path_)) {
    failed_ = true;
    return false;
  }

  file_.reset(base::OpenFile(path_, "wb"));
  if (file_.get() == nullptr)
    failed_ = true;

  // Allocate the header.
  Position pos = Allocate(sizeof(MINIDUMP_HEADER));
  DCHECK_EQ(kHeaderPos, pos);

  return succeeded();
}

bool MinidumpSerializer::SerializeThreads(
    const std::vector<std::pair<std::string, std::string>>& raw_threads) {
  if (raw_threads.empty())
    return succeeded();

  std::vector<MINIDUMP_THREAD> threads;
  threads.resize(raw_threads.size());

  for (int i = 0; i < threads.size(); ++i) {
    // Write the context.
    DCHECK_EQ(sizeof(CONTEXT), raw_threads[i].second.length());
    Position pos = AppendBytes(raw_threads[i].second);

    // Copy thread to vector for more efficient serialization, then set Rvas.
    DCHECK_EQ(sizeof(MINIDUMP_THREAD), raw_threads[i].first.length());
    memcpy(&threads.at(i), raw_threads[i].first.c_str(),
           sizeof(MINIDUMP_THREAD));

    MINIDUMP_THREAD& thread = threads[i];
    refinery::AddressRange stack_range(thread.Stack.StartOfMemoryRange,
                                       thread.Stack.Memory.DataSize);
    if (!GetPos(stack_range, &thread.Stack.Memory.Rva))
      failed_ = true;
    thread.ThreadContext.Rva = pos;
  }

  AppendStream(ThreadListStream, threads);
  return succeeded();
}

bool MinidumpSerializer::SerializeMemory(
    const std::map<refinery::Address, std::string>& regions) {
  is_serialize_memory_invoked_ = true;

  if (regions.empty())
    return succeeded();

  // Write bytes data and create the memory descriptors.
  std::vector<MINIDUMP_MEMORY_DESCRIPTOR> memory_descriptors;
  memory_descriptors.resize(regions.size());
  size_t idx = 0;
  for (const auto& region : regions) {
    refinery::AddressRange range(region.first, region.second.length());
    DCHECK(range.IsValid());

    Position pos = AppendBytes(region.second);
    auto inserted = memory_positions_.insert(std::make_pair(range, pos));
    DCHECK_EQ(true, inserted.second);

    memory_descriptors[idx].StartOfMemoryRange = range.start();
    memory_descriptors[idx].Memory.DataSize = range.size();
    memory_descriptors[idx].Memory.Rva = pos;

    ++idx;
  }

  // Write descriptors and create directory entry.
  AppendStream(MemoryListStream, memory_descriptors);

  return succeeded();
}

bool MinidumpSerializer::Finalize() {
  // Serialize the directory.
  Position pos = AppendVec(directory_);

  // Serialize the header.
  MINIDUMP_HEADER hdr;
  hdr.Signature = MINIDUMP_SIGNATURE;
  hdr.NumberOfStreams = directory_.size();
  hdr.StreamDirectoryRva = pos;
  Write(kHeaderPos, hdr);

  return succeeded();
}

MinidumpSerializer::Position MinidumpSerializer::Allocate(size_t size_bytes) {
  Position pos = cursor_;
  if (!IncrementCursor(size_bytes))
    failed_ = true;
  return pos;
}

template <class DataType>
MinidumpSerializer::Position MinidumpSerializer::Append(const DataType& data) {
  Position pos = Allocate(sizeof(data));
  Write(pos, data);
  return pos;
}

template <class DataType>
MinidumpSerializer::Position MinidumpSerializer::AppendVec(
    const std::vector<DataType>& data) {
  DCHECK(!data.empty());

  size_t size_bytes = sizeof(DataType) * data.size();
  Position pos = Allocate(size_bytes);
  WriteBytes(pos, size_bytes, &data.at(0));
  return pos;
}

template <class DataType>
MinidumpSerializer::Position MinidumpSerializer::AppendStream(
    MINIDUMP_STREAM_TYPE type,
    const std::vector<DataType>& elements) {
  DCHECK(!elements.empty());

  // Append the stream
  ULONG32 num_elements = elements.size();
  Position pos = Append(num_elements);
  AppendVec(elements);

  // Create its directory entry.
  MINIDUMP_DIRECTORY directory = {0};
  directory.StreamType = type;
  directory.Location.Rva = pos;
  directory.Location.DataSize =
      sizeof(ULONG32) + elements.size() * sizeof(DataType);
  directory_.push_back(directory);

  return pos;
}

MinidumpSerializer::Position MinidumpSerializer::AppendBytes(
    base::StringPiece data) {
  Position pos = Allocate(data.length());
  WriteBytes(pos, data.length(), data.data());
  return pos;
}

template <class DataType>
void MinidumpSerializer::Write(Position pos, const DataType& data) {
  WriteBytes(pos, sizeof(data), &data);
}

void MinidumpSerializer::WriteBytes(Position pos,
                                    size_t size_bytes,
                                    const void* data) {
  if (failed_)
    return;

  // Validate the write does not go past the cursor.
  base::CheckedNumeric<Position> pos_end = pos;
  pos_end += size_bytes;
  DCHECK(pos_end.IsValid());
  DCHECK(pos_end.ValueOrDie() <= cursor_);

  DCHECK(file_.get() != nullptr);

  // Seek and write.
  if (fseek(file_.get(), pos, SEEK_SET) != 0) {
    failed_ = true;
    return;
  }
  if (fwrite(data, sizeof(char), size_bytes, file_.get()) != size_bytes) {
    failed_ = true;
    return;
  }
}

bool MinidumpSerializer::IncrementCursor(size_t size_bytes) {
  base::CheckedNumeric<Position> cur = cursor_;
  cur += size_bytes;
  if (!cur.IsValid())
    return false;

  cursor_ += size_bytes;
  return true;
}

bool MinidumpSerializer::GetPos(const refinery::AddressRange& range,
                                Position* pos) const {
  DCHECK(range.IsValid());
  DCHECK(pos != nullptr);
  DCHECK(is_serialize_memory_invoked_);

  auto it = memory_positions_.upper_bound(range);
  if (it == memory_positions_.begin())
    return false;

  // Note: given that memory ranges do not overlap, only the immediate
  // predecessor is a candidate match.
  --it;
  if (it->first.Spans(range)) {
    *pos = it->second;
    return true;
  }

  return false;
}

}  // namespace

MinidumpSpecification::MinidumpSpecification() {
}

bool MinidumpSpecification::AddThread(const void* thread_data,
                                      size_t thread_size_bytes,
                                      const void* context_data,
                                      size_t context_size_bytes) {
  DCHECK(thread_data != nullptr);
  DCHECK_EQ(sizeof(MINIDUMP_THREAD), thread_size_bytes);
  DCHECK_GT(thread_size_bytes, 0U);
  DCHECK(context_data != nullptr);
  DCHECK_EQ(sizeof(CONTEXT), context_size_bytes);
  DCHECK_GT(context_size_bytes, 0U);

  threads_.push_back(std::make_pair(std::string(), std::string()));
  auto& inserted = threads_[threads_.size() - 1];
  inserted.first.resize(thread_size_bytes);
  memcpy(&inserted.first.at(0), thread_data, thread_size_bytes);
  inserted.second.resize(context_size_bytes);
  memcpy(&inserted.second.at(0), context_data, context_size_bytes);

  return true;
}

bool MinidumpSpecification::AddMemoryRegion(refinery::Address addr,
                                            base::StringPiece bytes) {
  return AddMemoryRegion(addr, bytes.data(), bytes.length());
}

bool MinidumpSpecification::AddMemoryRegion(refinery::Address addr,
                                            const void* data,
                                            size_t size_bytes) {
  DCHECK(data != nullptr);

  // Ensure range validity.
  refinery::AddressRange range(addr, size_bytes);
  if (!range.IsValid())
    return false;

  // Overlap is not supported at this point - check with successor and
  // predecessor.
  auto it = memory_regions_.upper_bound(addr);

  if (it != memory_regions_.end()) {
    refinery::AddressRange post_range(it->first, it->second.length());
    DCHECK(post_range.IsValid());
    if (range.Intersects(post_range))
      return false;
  }

  if (it != memory_regions_.begin()) {
    --it;
    refinery::AddressRange pre_range(it->first, it->second.length());
    DCHECK(pre_range.IsValid());
    if (range.Intersects(pre_range))
      return false;
  }

  // Insert (in two stages, to avoid copying).
  auto inserted =
      memory_regions_.insert(std::make_pair(addr, std::string()));
  if (!inserted.second)
    return false;
  inserted.first->second.insert(0, static_cast<const char*>(data), size_bytes);
  return true;
}

bool MinidumpSpecification::Serialize(const base::ScopedTempDir& dir,
                                      base::FilePath* path) const {
  MinidumpSerializer serializer;
  bool success = serializer.Initialize(dir) &&
                 serializer.SerializeMemory(memory_regions_) &&
                 serializer.SerializeThreads(threads_) &&
                 serializer.Finalize();
  *path = serializer.path();
  return success;
}

}  // namespace testing
