// Copyright 2012 Google Inc.
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
// This file implements the TraceFileWriter and TraceFileWriterFactory classes
// which provide an implementation and factory, respectively, for the default
// buffer consumer used by the call trace service.

#include "syzygy/trace/service/trace_file_writer.h"

#include <time.h>

#include "base/atomicops.h"
#include "base/bind.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/stringprintf.h"
#include "base/memory/scoped_ptr.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/common/align.h"
#include "syzygy/common/buffer_writer.h"
#include "syzygy/common/path_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/service/buffer_pool.h"
#include "syzygy/trace/service/session.h"
#include "syzygy/trace/service/trace_file_writer_factory.h"

namespace trace {
namespace service {

namespace {

FilePath GenerateTraceFileName(const Session* session,
                               const FilePath& trace_directory ) {
  DCHECK(session != NULL);
  DCHECK(!trace_directory.empty());

  const ProcessInfo& client = session->client_info();

  // We use the current time to disambiguate the trace file, so let's look
  // at the clock.
  time_t t = time(NULL);
  struct tm local_time = {};
  ::localtime_s(&local_time, &t);

  // Construct the trace file path from the program being run, the current
  // timestamp, and the process id.
  return trace_directory.Append(base::StringPrintf(
      L"trace-%ls-%4d%02d%02d%02d%02d%02d-%d.bin",
      client.executable_path.BaseName().value().c_str(),
      1900 + local_time.tm_year,
      1 + local_time.tm_mon,
      local_time.tm_mday,
      local_time.tm_hour,
      local_time.tm_min,
      local_time.tm_sec,
      client.process_id));
}

bool OpenTraceFile(const FilePath& file_path,
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
               << "' for writing: " << com::LogWe(error) << ".";
    return false;
  }

  file_handle->Set(new_file_handle.Take());

  return true;
}

bool GetBlockSize(const FilePath& path, size_t* block_size) {
  wchar_t volume[MAX_PATH];

  if (!::GetVolumePathName(path.value().c_str(), volume, arraysize(volume))) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get volume path name: " << com::LogWe(error)
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
    LOG(ERROR) << "Failed to get volume info: " << com::LogWe(error) << ".";
    return false;
  }

  *block_size = bytes_per_sector;
  return true;
}

bool WriteTraceFileHeader(HANDLE file_handle,
                          const Session* session,
                          size_t block_size) {
  DCHECK(file_handle != INVALID_HANDLE_VALUE);
  DCHECK(session != NULL);
  DCHECK(block_size != 0);

  const ProcessInfo& client = session->client_info();

  // Make the initial buffer big enough to hold the header without the
  // variable length blob, then skip past the fixed sized portion of the
  // header.
  std::vector<uint8> buffer;
  buffer.reserve(16 * 1024);
  common::VectorBufferWriter writer(&buffer);
  if (!writer.Consume(offsetof(TraceFileHeader, blob_data)))
    return false;

  // Populate the fixed sized portion of the header.
  TraceFileHeader* header = reinterpret_cast<TraceFileHeader*>(&buffer[0]);
  ::memcpy(&header->signature,
           &TraceFileHeader::kSignatureValue,
           sizeof(header->signature));
  header->server_version.lo = TRACE_VERSION_LO;
  header->server_version.hi = TRACE_VERSION_HI;
  header->timestamp = ::GetTickCount();
  header->process_id = client.process_id;
  header->block_size = block_size;
  header->module_base_address = client.exe_base_address;
  header->module_size = client.exe_image_size;
  header->module_checksum = client.exe_checksum;
  header->module_time_date_stamp = client.exe_time_date_stamp;
  header->os_version_info = client.os_version_info;
  header->system_info = client.system_info;
  header->memory_status = client.memory_status;

  // Make sure we record the path to the executable as a path with a drive
  // letter, rather than using device names.
  FilePath drive_path;
  if (!common::ConvertDevicePathToDrivePath(client.executable_path,
                                            &drive_path)) {
    return false;
  }

  // Populate the blob with the variable length fields.
  if (!writer.WriteString(drive_path.value()))
    return false;
  if (!writer.WriteString(client.command_line))
    return false;
  if (!writer.Write(client.environment.size(), &client.environment[0]))
    return false;

  // Update the final header size and align to a block size.
  header->header_size = buffer.size();
  writer.Align(header->block_size);

  // Commit the header page to disk.
  DWORD bytes_written = 0;
  if (!::WriteFile(file_handle, &buffer[0], buffer.size(), &bytes_written,
                   NULL) || bytes_written != buffer.size() ) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed writing trace file header: " << com::LogWe(error)
               << ".";
    return false;
  }

  return true;
}

}  // namespace

TraceFileWriter::TraceFileWriter(MessageLoop* message_loop,
                                 const FilePath& trace_directory)
    : message_loop_(message_loop),
      trace_file_path_(trace_directory),  // Will mutate to filename on Open().
      block_size_(0) {
  DCHECK(message_loop != NULL);
  DCHECK(!trace_directory.empty());
}

bool TraceFileWriter::Open(Session* session) {
  DCHECK(session != NULL);
  DCHECK(!trace_file_handle_.IsValid());

  if (!file_util::CreateDirectory(trace_file_path_)) {
    LOG(ERROR) << "Failed to create trace directory: '"
               << trace_file_path_.value() << "'.";
    return false;
  }

  // Append the trace file name onto the trace file directory we stored on
  // construction.
  trace_file_path_ = GenerateTraceFileName(session, trace_file_path_);

  // Open the trace file.
  base::win::ScopedHandle temp_handle;
  if (!OpenTraceFile(trace_file_path_, &temp_handle)) {
    LOG(ERROR) << "Failed to open trace file: '"
               << trace_file_path_.value() << "'.";
    return false;
  }

  // Figure out how big a physical block is on the disk.
  if (!GetBlockSize(trace_file_path_, &block_size_)) {
    LOG(ERROR) << "Failed to determine the trace file block size.";
    return false;
  }

  // Write the trace file header.
  if (!WriteTraceFileHeader(temp_handle, session, block_size_)) {
    LOG(ERROR) << "Failed to write trace file header.";
    return false;
  }

  trace_file_handle_.Set(temp_handle.Take());

  return true;
}

bool TraceFileWriter::Close(Session* /* session */) {
  return true;
}

bool TraceFileWriter::ConsumeBuffer(Buffer* buffer) {
  DCHECK(buffer != NULL);
  DCHECK(buffer->session != NULL);
  DCHECK(message_loop_ != NULL);
  DCHECK(trace_file_handle_.IsValid());

  message_loop_->PostTask(FROM_HERE,
                          base::Bind(&TraceFileWriter::WriteBuffer,
                                     this,
                                     scoped_refptr<Session>(buffer->session),
                                     base::Unretained(buffer)));

  return true;
}

size_t TraceFileWriter::block_size() const {
  return block_size_;
}

void TraceFileWriter::WriteBuffer(Session* session,
                                  Buffer* buffer) {
  DCHECK(session != NULL);
  DCHECK(buffer != NULL);
  DCHECK_EQ(session, buffer->session);
  DCHECK_EQ(Buffer::kPendingWrite, buffer->state);
  DCHECK_EQ(MessageLoop::current(), message_loop_);
  DCHECK(trace_file_handle_.IsValid());

  // Parse the record prefix and segment header;
  volatile RecordPrefix* prefix =
      reinterpret_cast<RecordPrefix*>(buffer->data_ptr);
  volatile TraceFileSegmentHeader* header =
      reinterpret_cast<volatile TraceFileSegmentHeader*>(prefix + 1);

  // Let's not trust the client to stop playing with the buffer while
  // we're writing. Whatever the length is now, is what we'll use.
  size_t segment_length = header->segment_length;
  const size_t kHeaderLength = sizeof(*prefix) + sizeof(*header);
  if (segment_length > 0) {
    size_t bytes_to_write = common::AlignUp(kHeaderLength + segment_length,
                                            block_size_);
    if (prefix->type != TraceFileSegmentHeader::kTypeId ||
        prefix->size != sizeof(TraceFileSegmentHeader) ||
        prefix->version.hi != TRACE_VERSION_HI ||
        prefix->version.lo != TRACE_VERSION_LO) {
      LOG(WARNING) << "Dropped buffer: invalid segment header.";
    } else if (bytes_to_write > buffer->buffer_size) {
      LOG(WARNING) << "Dropped buffer: bytes written exceeds buffer size.";
    } else {
      // Commit the buffer to disk.
      // TODO(rogerm): Use overlapped I/O.
      DCHECK(bytes_to_write != 0);
      DWORD bytes_written = 0;
      if (!::WriteFile(trace_file_handle_,
                       buffer->data_ptr,
                       bytes_to_write,
                       &bytes_written,
                       NULL) ||
          bytes_written != bytes_to_write) {
        DWORD error = ::GetLastError();
        LOG(ERROR) << "Failed writing to '" << trace_file_path_.value()
                   << "': " << com::LogWe(error) << ".";
      }
    }
  }

  session->RecycleBuffer(buffer);
}

}  // namespace service
}  // namespace trace
