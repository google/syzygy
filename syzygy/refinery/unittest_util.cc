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
  template <class DataType>
  Position AppendVec(const std::vector<DataType>& data);
  Position AppendBytes(base::StringPiece data);

  // Write to already allocated space.
  template <class DataType>
  void Write(Position pos, const DataType& data);
  void WriteBytes(Position pos, size_t size_bytes, const void* data);

  bool IncrementCursor(size_t size_bytes);

  bool success() const { return !failed_; }

  bool failed_;

  std::vector<MINIDUMP_DIRECTORY> directory_;

  Position cursor_;  // The next allocatable position.
  base::FilePath path_;
  base::ScopedFILE file_;
};

MinidumpSerializer::MinidumpSerializer() : failed_(true) {
}

bool MinidumpSerializer::Initialize(const base::ScopedTempDir& dir) {
  DCHECK(dir.IsValid());

  failed_ = false;
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

  return success();
}

bool MinidumpSerializer::SerializeMemory(
    const std::map<refinery::Address, std::string>& regions) {
  std::vector<MINIDUMP_MEMORY_DESCRIPTOR> memory_descriptors;
  memory_descriptors.resize(regions.size());

  size_t idx = 0;
  for (const auto& region : regions) {
    refinery::AddressRange range(region.first, region.second.length());
    DCHECK(range.IsValid());

    // Fill the descriptor and write the data.
    memory_descriptors[idx].StartOfMemoryRange = range.start();
    memory_descriptors[idx].Memory.DataSize = range.size();
    memory_descriptors[idx].Memory.Rva = AppendBytes(region.second);

    ++idx;
  }

  // Fill the directory entry and write the descriptors.
  ULONG32 num_ranges = memory_descriptors.size();

  MINIDUMP_DIRECTORY directory = {0};
  directory.StreamType = MemoryListStream;
  directory.Location.Rva = Append(num_ranges);
  directory.Location.DataSize =
      sizeof(ULONG32) +
      memory_descriptors.size() * sizeof(MINIDUMP_MEMORY_DESCRIPTOR);
  directory_.push_back(directory);

  AppendVec(memory_descriptors);

  return success();
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

  return success();
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
  size_t size_bytes = sizeof(DataType) * data.size();
  Position pos = Allocate(size_bytes);
  WriteBytes(pos, size_bytes, &data.at(0));
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

}  // namespace

MinidumpSpecification::MinidumpSpecification() {
}

bool MinidumpSpecification::AddMemoryRegion(refinery::Address addr,
                                            base::StringPiece bytes) {
  // Ensure range validity.
  refinery::AddressRange range(addr, bytes.length());
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

  // Insert.
  auto inserted =
      memory_regions_.insert(std::make_pair(addr, bytes.as_string()));
  return inserted.second;
}

bool MinidumpSpecification::Serialize(const base::ScopedTempDir& dir,
                                      base::FilePath* path) const {
  MinidumpSerializer serializer;
  bool success = serializer.Initialize(dir) &&
                 serializer.SerializeMemory(memory_regions_) &&
                 serializer.Finalize();
  *path = serializer.path();
  return success;
}

}  // namespace testing
