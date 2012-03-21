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
// This file implements the trace::service::Session class, which manages
// the trace file and buffers for a given client of the call trace service.

#include "syzygy/trace/service/session.h"

#include <time.h>

#include "base/command_line.h"
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/common/align.h"
#include "syzygy/common/buffer_writer.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/service/service.h"

namespace {

using trace::service::Buffer;
using trace::service::ProcessID;
using trace::service::ProcessInfo;

FilePath GenerateTraceFileName(const FilePath& trace_directory,
                               const ProcessInfo& client) {
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
                          const ProcessInfo& client,
                          size_t block_size) {
  DCHECK(file_handle != INVALID_HANDLE_VALUE);
  DCHECK(block_size != 0);

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

  // Populate the blob with the variable length fields.
  if (!writer.WriteString(client.executable_path.value()))
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

// Helper for logging Buffer::ID values.
std::ostream& operator << (std::ostream& stream, const Buffer::ID buffer_id) {
  return stream << "shared_memory_handle=0x" << std::hex << buffer_id.first
                << ", buffer_offset=0x" << std::hex << buffer_id.second;
}

}  // namespace

namespace trace {
namespace service {

Session::Session(Service* call_trace_service)
    : call_trace_service_(call_trace_service),
      buffers_pending_write_(0),
      is_closing_(false),
      input_error_already_logged_(false) {
  DCHECK(call_trace_service != NULL);
}

Session::~Session() {
  DCHECK(buffers_in_use_.empty());

  // Not strictly necessary, but let's make sure nothing refers to the
  // client buffers before we delete the underlying memory.
  buffers_available_.clear();

  // The session owns all of its shared memory buffers using raw pointers
  // inserted into the shared_memory_buffers_ list.
  while (!shared_memory_buffers_.empty()) {
    BufferPool* pool = shared_memory_buffers_.back();
    shared_memory_buffers_.pop_back();
    delete pool;
  }
}

bool Session::Init(const FilePath& trace_directory,
                   ProcessID client_process_id) {
  DCHECK(!trace_directory.empty());

  if (!client_.Initialize(client_process_id)) {
    LOG(ERROR) << "Failed to initialize client info.";
    return false;
  }

  trace_file_path_ = GenerateTraceFileName(trace_directory, client_);

  if (!OpenTraceFile(trace_file_path_, &trace_file_handle_)) {
    LOG(ERROR) << "Failed to open trace file: "
               << trace_file_path_.value().c_str();
    return false;
  }

  if (!GetBlockSize(trace_file_path_, &block_size_)) {
    LOG(ERROR) << "Failed to determine the trace file block size.";
    return false;
  }

  if (!WriteTraceFileHeader(trace_file_handle_, client_, block_size_)) {
    LOG(ERROR) << "Failed to write trace file header.";
    return false;
  }

  return true;
}

bool Session::Close() {
  std::vector<Buffer*> buffers;

  {
    base::AutoLock lock(lock_);

    // It's possible that the service is being stopped just after this session
    // was marked for closure. The service would then attempt to re-close the
    // session. Let's ignore these requests.
    if (is_closing_)
      return true;

    // We'll reserve space for the the worst case scenario buffer count.
    buffers.reserve(buffers_in_use_.size() + 1);

    // Otherwise the session is being asked to close for the first time.
    is_closing_ = true;

    // Schedule any outstanding buffers for flushing.
    BufferMap::iterator iter = buffers_in_use_.begin();
    for (; iter != buffers_in_use_.end(); ++iter) {
      if (!iter->second->write_is_pending) {
        MarkAsPendingWrite(iter->second);
        buffers.push_back(iter->second);
      }
    }

    // Create a process ended event. This causes at least one buffer to be in
    // use to store the process ended event.
    Buffer* buffer = NULL;
    if (!CreateProcessEndedEvent(&buffer))
      return false;
    DCHECK(buffer != NULL);
    DCHECK(!buffers_in_use_.empty());
    MarkAsPendingWrite(buffer);
    buffers.push_back(buffer);
  }

  if (!call_trace_service_->ScheduleBuffersForWriting(buffers)) {
    LOG(ERROR) << "Unable to schedule outstanding buffers for writing.";
    return false;
  }

  return true;
}

bool Session::FindBuffer(CallTraceBuffer* call_trace_buffer,
                         Buffer** client_buffer) {
  DCHECK(call_trace_buffer != NULL);
  DCHECK(client_buffer != NULL);

  base::AutoLock lock(lock_);

  Buffer::ID buffer_id = Buffer::GetID(*call_trace_buffer);

  BufferMap::iterator iter = buffers_in_use_.find(buffer_id);
  if (iter == buffers_in_use_.end()) {
    if (!input_error_already_logged_) {
      LOG(ERROR) << "Received call trace buffer not in use for this session "
                 << "[pid=" << client_.process_id << ", " << buffer_id << "].";
      input_error_already_logged_ = true;
    }
    return false;
  }

#ifndef NDEBUG
  // Make sure fields that are not part of the ID also match. The client
  // shouldnt' be playing with any of the call_trace_buffer fields.
  if (call_trace_buffer->mapping_size != iter->second->mapping_size ||
      call_trace_buffer->buffer_size != iter->second->buffer_size) {
    LOG(WARNING) << "Received call trace buffer with mismatched attributes.";
  }
#endif

  *client_buffer = iter->second;
  return true;
}

bool Session::GetNextBuffer(Buffer** out_buffer) {
  DCHECK(out_buffer != NULL);

  *out_buffer = NULL;
  base::AutoLock lock(lock_);

  // Once we're closing we should not hand out any more buffers.
  if (is_closing_) {
    LOG(ERROR) << "Session is closing but someone is trying to get a buffer.";
    return false;
  }

  return GetNextBufferUnlocked(out_buffer);
}

bool Session::ReturnBuffer(Buffer* buffer) {
  DCHECK(buffer != NULL);
  DCHECK(buffer->session == this);

  {
    base::AutoLock lock(lock_);

    // The buffer should not already be pending a write.
    if (buffer->write_is_pending) {
      LOG(ERROR) << "Buffer to be returned is already pending a write.";
      return false;
    }

    MarkAsPendingWrite(buffer);
  }

  // Schedule it for writing.
  if (!call_trace_service_->ScheduleBufferForWriting(buffer)) {
    LOG(ERROR) << "Unable to schedule buffer for writing.";
    return false;
  }

  return true;
}

bool Session::RecycleBuffer(Buffer* buffer) {
  DCHECK(buffer != NULL);
  DCHECK(buffer->session == this);

  // We take pains to use a manual lock here as we may end up calling our own
  // destructor. If we use an AutoLock, the lock no longer exists when
  // destroying the AutoLock and things blow up.
  lock_.Acquire();

  // The buffer should no longer be pending a write. This should have been
  // cleared by the write queue.
  if (buffer->write_is_pending) {
    LOG(ERROR) << "Buffer to be recycled is still pending a write.";
    lock_.Release();
    return false;
  }

  Buffer::ID buffer_id = Buffer::GetID(*buffer);
  if (buffers_in_use_.erase(buffer_id) == 0) {
    LOG(ERROR) << "Buffer is not recorded as being in use ("
               << buffer_id << ").";
    lock_.Release();
    return false;
  }

  --buffers_pending_write_;
  DCHECK_LE(buffers_pending_write_, buffers_in_use_.size());

  buffers_available_.push_front(buffer);

  // If the session is closing and all outstanding buffers have been recycled
  // then it's safe to destroy this session.
  if (is_closing_ && buffers_in_use_.empty()) {
    DCHECK_EQ(0u, buffers_pending_write_);
    // This indirectly calls our destructor, so we can't have an AutoLock
    // referring to lock_.
    return call_trace_service_->DestroySession(this);
  }

  lock_.Release();
  return true;
}

void Session::MarkAsPendingWrite(Buffer* buffer) {
  DCHECK(buffer != NULL);
  lock_.AssertAcquired();

  DCHECK(!buffer->write_is_pending);
  DCHECK(buffers_in_use_.find(Buffer::GetID(*buffer)) !=
      buffers_in_use_.end());

  // Mark this buffer as pending a write.
  buffer->write_is_pending = true;
  ++buffers_pending_write_;
  DCHECK_LE(buffers_pending_write_, buffers_in_use_.size());
}

bool Session::AllocateBuffers(size_t num_buffers, size_t buffer_size) {
  DCHECK_GT(num_buffers, 0u);
  DCHECK_GT(buffer_size, 0u);
  lock_.AssertAcquired();

  // Allocate the record for the shared memory buffer.
  scoped_ptr<BufferPool> pool(new BufferPool());
  if (pool.get() == NULL) {
    LOG(ERROR) << "Failed to allocate shared memory buffer.";
    return false;
  }

  // Initialize the shared buffer pool.
  buffer_size = common::AlignUp(buffer_size, block_size());
  if (!pool->Init(this, client_.process_handle, num_buffers,
                  buffer_size)) {
    LOG(ERROR) << "Failed to initialize shared memory buffer.";
    return false;
  }

  // Save the shared memory block so that it's managed by the session.
  shared_memory_buffers_.push_back(pool.get());
  BufferPool* pool_ptr = pool.release();

  // Put the client buffers into the list of available buffers.
  for (Buffer* buf = pool_ptr->begin(); buf != pool_ptr->end(); ++buf) {
    buffers_available_.push_back(buf);
  }

  return true;
}

bool Session::GetNextBufferUnlocked(Buffer** out_buffer) {
  DCHECK(out_buffer != NULL);
  lock_.AssertAcquired();

  *out_buffer = NULL;

  if (buffers_available_.empty()) {
    // TODO(chrisha): This is where back-pressure will be applied.
    if (!AllocateBuffers(call_trace_service_->num_incremental_buffers(),
                         call_trace_service_->buffer_size_in_bytes())) {
      return false;
    }
  }
  DCHECK(!buffers_available_.empty());

  Buffer* buffer = buffers_available_.front();
  buffers_available_.pop_front();
  buffers_in_use_[Buffer::GetID(*buffer)] = buffer;

  *out_buffer = buffer;
  return true;
}

bool Session::CreateProcessEndedEvent(Buffer** buffer) {
  DCHECK(buffer != NULL);
  lock_.AssertAcquired();

  *buffer = NULL;

  // We output a segment that contains a single empty event. That is, the
  // event consists only of a prefix whose data size is set to zero. The buffer
  // will be populated with the following:
  //
  // RecordPrefix: the prefix for the TraceFileSegmentHeader which follows
  //     (with type TraceFileSegmentHeader::kTypeId).
  // TraceFileSegmentHeader: the segment header for the segment represented
  //     by this buffer.
  // RecordPrefix: the prefix for the event itself (with type
  //     TRACE_PROCESS_ENDED). This prefix will have a data size of zero
  //     indicating that no structure follows.
  const size_t kBufferSize = sizeof(RecordPrefix) +
      sizeof(TraceFileSegmentHeader) + sizeof(RecordPrefix);

  // Ensure that a free buffer exists.
  if (buffers_available_.empty()) {
    if (!AllocateBuffers(1, kBufferSize)) {
      LOG(ERROR) << "Unable to allocate buffer for process ended event.";
      return false;
    }
  }
  DCHECK(!buffers_available_.empty());

  // Get a buffer for the event.
  if (!GetNextBufferUnlocked(buffer) || *buffer == NULL) {
    LOG(ERROR) << "Unable to get a buffer for process ended event.";
    return false;
  }
  DCHECK(*buffer != NULL);

  // This should pretty much never happen as we always allocate really big
  // buffers, but it is possible.
  if ((*buffer)->buffer_size < kBufferSize) {
    LOG(ERROR) << "Buffer too small for process ended event.";
    return false;
  }

  // Populate the various structures in the buffer.

  RecordPrefix* segment_prefix =
      reinterpret_cast<RecordPrefix*>((*buffer)->data_ptr);
  DWORD timestamp = ::GetTickCount();
  segment_prefix->timestamp = timestamp;
  segment_prefix->size = sizeof(TraceFileSegmentHeader);
  segment_prefix->type = TraceFileSegmentHeader::kTypeId;
  segment_prefix->version.hi = TRACE_VERSION_HI;
  segment_prefix->version.lo = TRACE_VERSION_LO;

  TraceFileSegmentHeader* segment_header =
      reinterpret_cast<TraceFileSegmentHeader*>(segment_prefix + 1);
  segment_header->thread_id = 0;
  segment_header->segment_length = sizeof(RecordPrefix);

  RecordPrefix* event_prefix =
      reinterpret_cast<RecordPrefix*>(segment_header + 1);
  event_prefix->timestamp = timestamp;
  event_prefix->size = 0;
  event_prefix->type = TRACE_PROCESS_ENDED;
  event_prefix->version.hi = TRACE_VERSION_HI;
  event_prefix->version.lo = TRACE_VERSION_LO;

  return true;
}

}  // namespace trace::service
}  // namespace trace
