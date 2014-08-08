// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/trace/service/trace_file_writer.h"

#include <time.h>

#include "base/strings/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/common/buffer_writer.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/path_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace trace {
namespace service {

namespace {

bool OpenTraceFile(const base::FilePath& file_path,
                   base::win::ScopedHandle* file_handle) {
  DCHECK(!file_path.empty());
  DCHECK(file_handle != NULL);

  // Create a new trace file.
  base::win::ScopedHandle new_file_handle(
      ::CreateFile(file_path.value().c_str(),
                   GENERIC_READ | GENERIC_WRITE,
                   FILE_SHARE_DELETE | FILE_SHARE_READ,
                   NULL, /* lpSecurityAttributes */
                   CREATE_ALWAYS,
                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING,
                   NULL /* hTemplateFile */));
  if (!new_file_handle.IsValid()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to open '" << file_path.value()
               << "' for writing: " << ::common::LogWe(error) << ".";
    return false;
  }

  file_handle->Set(new_file_handle.Take());

  return true;
}

bool GetBlockSize(const base::FilePath& path, size_t* block_size) {
  wchar_t volume[MAX_PATH];

  if (!::GetVolumePathName(path.value().c_str(), volume, arraysize(volume))) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get volume path name: " << ::common::LogWe(error)
               << ".";
    return false;
  }

  DWORD sectors_per_cluster = 0;
  DWORD bytes_per_sector = 0;
  DWORD free_clusters = 0;
  DWORD total_clusters = 0;

  if (!::GetDiskFreeSpace(volume, &sectors_per_cluster, &bytes_per_sector,
                          &free_clusters, &total_clusters)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get volume info: " << ::common::LogWe(error)
               << ".";
    return false;
  }

  *block_size = bytes_per_sector;
  return true;
}

}  // namespace

TraceFileWriter::TraceFileWriter() : block_size_(0) {
}

TraceFileWriter::~TraceFileWriter() {
}

base::FilePath TraceFileWriter::GenerateTraceFileBaseName(
    const ProcessInfo& process_info) {
  // We use the current time to disambiguate the trace file, so let's look
  // at the clock.
  time_t t = time(NULL);
  struct tm local_time = {};
  ::localtime_s(&local_time, &t);

  // Construct the trace file path from the program being run, the current
  // timestamp, and the process id.
  return base::FilePath(base::StringPrintf(
      L"trace-%ls-%4d%02d%02d%02d%02d%02d-%d.bin",
      process_info.executable_path.BaseName().value().c_str(),
      1900 + local_time.tm_year,
      1 + local_time.tm_mon,
      local_time.tm_mday,
      local_time.tm_hour,
      local_time.tm_min,
      local_time.tm_sec,
      process_info.process_id));
}

bool TraceFileWriter::Open(const base::FilePath& path) {
  // Open the trace file.
  base::win::ScopedHandle temp_handle;
  if (!OpenTraceFile(path, &temp_handle)) {
    LOG(ERROR) << "Failed to open trace file: '"
               << path_.value() << "'.";
    return false;
  }

  // Figure out how big a physical block is on the disk.
  size_t block_size;
  if (!GetBlockSize(path, &block_size)) {
    LOG(ERROR) << "Failed to determine the trace file block size.";
    return false;
  }

  path_ = path;
  handle_.Set(temp_handle.Take());
  block_size_ = block_size;

  return true;
}

bool TraceFileWriter::WriteHeader(const ProcessInfo& process_info) {
  // Make sure we record the path to the executable as a path with a drive
  // letter, rather than using device names.
  base::FilePath drive_path;
  if (!::common::ConvertDevicePathToDrivePath(process_info.executable_path,
                                              &drive_path)) {
    return false;
  }

  // Allocate an initial buffer to which to write the trace file header.
  std::vector<uint8> buffer;
  buffer.reserve(32 * 1024);

  // Skip past the fixed sized portion of the header and populate the variable
  // length fields.
  ::common::VectorBufferWriter writer(&buffer);
  if (!writer.Consume(offsetof(TraceFileHeader, blob_data)) ||
      !writer.WriteString(drive_path.value()) ||
      !writer.WriteString(process_info.command_line) ||
      !writer.Write(process_info.environment.size(),
                    &process_info.environment[0])) {
    return false;
  }

  // Go back and populate the fixed sized portion of the header.
  TraceFileHeader* header = reinterpret_cast<TraceFileHeader*>(&buffer[0]);
  ::memcpy(&header->signature,
           &TraceFileHeader::kSignatureValue,
           sizeof(header->signature));
  header->server_version.lo = TRACE_VERSION_LO;
  header->server_version.hi = TRACE_VERSION_HI;
  header->header_size = buffer.size();
  header->block_size = block_size_;
  header->process_id = process_info.process_id;
  header->module_base_address = process_info.exe_base_address;
  header->module_size = process_info.exe_image_size;
  header->module_checksum = process_info.exe_checksum;
  header->module_time_date_stamp = process_info.exe_time_date_stamp;
  header->os_version_info = process_info.os_version_info;
  header->system_info = process_info.system_info;
  header->memory_status = process_info.memory_status;
  trace::common::GetClockInfo(&header->clock_info);

  // Align the header buffer up to the block size.
  writer.Align(block_size_);

  // Commit the header page to disk.
  DWORD bytes_written = 0;
  if (!::WriteFile(handle_.Get(), &buffer[0], buffer.size(), &bytes_written,
                   NULL) || bytes_written != buffer.size() ) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed writing trace file header: " << ::common::LogWe(error)
               << ".";
    return false;
  }

  return true;
}

bool TraceFileWriter::WriteRecord(const void* data, size_t length) {
  DCHECK(data != NULL);

  const size_t kHeaderLength =
      sizeof(RecordPrefix) + sizeof(TraceFileSegmentHeader);

  if (length < kHeaderLength) {
    LOG(ERROR) << "Dropped buffer: too short.";
    return false;
  }

  // We currently can only handle records that contain a TraceFileSegmentHeader.
  const RecordPrefix* record = reinterpret_cast<const RecordPrefix*>(data);
  if (record->type != TraceFileSegmentHeader::kTypeId ||
      record->size != sizeof(TraceFileSegmentHeader) ||
      record->version.hi != TRACE_VERSION_HI ||
      record->version.lo != TRACE_VERSION_LO) {
    LOG(ERROR) << "Dropped buffer: invalid RecordPrefix.";
    return false;
  }

  // Let's not trust the client to stop playing with the buffer while
  // we're writing. Whatever the length is now, is what we'll use. If the
  // segment itself is empty we simply skip writing the buffer.
  const TraceFileSegmentHeader* header =
      reinterpret_cast<const TraceFileSegmentHeader*>(record + 1);
  size_t segment_length = header->segment_length;
  if (segment_length == 0) {
    LOG(INFO) << "Not writing empty buffer.";
    return true;
  }

  // Figure out the total size that we'll write to disk.
  size_t bytes_to_write = ::common::AlignUp(kHeaderLength + segment_length,
                                            block_size_);

  // Ensure that the total number of bytes to write does not exceed the
  // maximum record length.
  if (bytes_to_write > length) {
    LOG(ERROR) << "Dropped buffer: bytes written exceeds buffer size.";
    return false;
  }

  // Commit the buffer to disk.
  // TODO(rogerm): Use overlapped I/O.
  DCHECK_LT(0u, bytes_to_write);
  DWORD bytes_written = 0;
  if (!::WriteFile(handle_.Get(),
                   record,
                   bytes_to_write,
                   &bytes_written,
                   NULL) ||
      bytes_written != bytes_to_write) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed writing to '" << path_.value()
               << "': " << ::common::LogWe(error) << ".";
    return false;
  }

  return true;
}

bool TraceFileWriter::Close() {
  if (::CloseHandle(handle_.Take()) == 0) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "CloseHandle failed: " << ::common::LogWe(error) << ".";
    return false;
  }
  return true;
}

}  // namespace service
}  // namespace trace
