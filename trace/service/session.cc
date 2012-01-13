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
// This file implements the call_trace::service::Session class, which manages
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
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/service/service.h"

namespace {

using call_trace::service::Buffer;
using call_trace::service::ProcessID;
using call_trace::service::ProcessInfo;

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

  // Calculate the space required for the header page and allocate a
  // buffer for it.
  size_t header_len = sizeof(TraceFileHeader) + (client.command_line.length() *
                                                 sizeof(wchar_t));
  size_t buffer_size = common::AlignUp(header_len, block_size);
  scoped_ptr_malloc<TraceFileHeader> header(
      static_cast<TraceFileHeader*>(::calloc(1, buffer_size)));

  // Populate the header values.
  ::memcpy(&header->signature,
           &TraceFileHeader::kSignatureValue,
           sizeof(header->signature));
  header->server_version.lo = TRACE_VERSION_LO;
  header->server_version.hi = TRACE_VERSION_HI;
  header->timestamp = ::GetTickCount();
  header->header_size = header_len;
  header->process_id = client.process_id;
  header->command_line_len = client.command_line.length();
  header->block_size = block_size;
  base::wcslcpy(&header->module_path[0],
                client.executable_path.value().c_str(),
                sizeof(header->module_path));
  header->module_base_address = client.exe_base_address;
  header->module_size = client.exe_image_size;
  header->module_checksum = client.exe_checksum;
  header->module_time_date_stamp = client.exe_time_date_stamp;
  base::wcslcpy(&header->command_line[0],
                client.command_line.c_str(),
                client.command_line.length() + 1);

  // Commit the header page to disk.
  DWORD bytes_written = 0;
  if (!::WriteFile(file_handle, header.get(), buffer_size, &bytes_written,
                   NULL) || bytes_written != buffer_size ) {
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

namespace call_trace {
namespace service {

Session::Session(Service* call_trace_service)
    : call_trace_service_(call_trace_service),
      is_closing_(false) {
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

bool Session::Close(BufferQueue* flush_queue, bool* can_destroy_now ) {
  DCHECK(can_destroy_now != NULL);
  DCHECK(flush_queue != NULL);

  // It's possible that the service is being stopped just after this session
  // was marked for closure. The service would then attempt to re-close the
  // session. Let's ignore these requests.
  if (is_closing_) {
    *can_destroy_now = false;
    return true;
  }

  // Otherwise the session is closing. If the session has no outstanding
  // buffers in use then it can be destroyed now. If the session has
  // outstanding buffers in use then these buffers need to be queued
  // for writing and the destruction of this session deferred; see
  // RecycleBuffer().
  is_closing_ = true;
  if (buffers_in_use_.empty()) {
    *can_destroy_now = true;
  } else {
    *can_destroy_now = false;
    BufferMap::iterator iter = buffers_in_use_.begin();
    for (; iter != buffers_in_use_.end(); ++iter) {
      if (!iter->second->write_is_pending) {
        iter->second->write_is_pending = true;
        flush_queue->push_back(iter->second);
      }
    }
  }

  return true;
}

bool Session::HasAvailableBuffers() const {
  return !buffers_available_.empty();
}

bool Session::AllocateBuffers(size_t num_buffers, size_t buffer_size) {
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

bool Session::FindBuffer(CallTraceBuffer* call_trace_buffer,
                         Buffer** client_buffer) {
  DCHECK(call_trace_buffer != NULL);
  DCHECK(client_buffer != NULL);

  Buffer::ID buffer_id = Buffer::GetID(*call_trace_buffer);

  BufferMap::iterator iter = buffers_in_use_.find(buffer_id);
  if (iter == buffers_in_use_.end()) {
    LOG(ERROR) << "Received call trace buffer not in use for this session "
               << "[pid=" << client_.process_id << ", " << buffer_id << "].";
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
  DCHECK(!buffers_available_.empty());

  Buffer* buffer = buffers_available_.front();
  buffers_available_.pop_front();
  buffers_in_use_[Buffer::GetID(*buffer)] = buffer;

  *out_buffer = buffer;
  return true;
}

bool Session::RecycleBuffer(Buffer* buffer) {
  DCHECK(buffer != NULL);
  DCHECK(buffer->session == this);

  Buffer::ID buffer_id = Buffer::GetID(*buffer);
  if (buffers_in_use_.erase(buffer_id) == 0) {
    LOG(ERROR) << "Buffer is not recorded as being in use ("
               << buffer_id << ").";
    return false;
  }

  buffers_available_.push_front(buffer);

  // If the session is closing and all outstanding buffers have been recycled
  // then it's safe to destroy this session.
  if (is_closing_ && buffers_in_use_.empty()) {
    return call_trace_service_->DestroySession(this);
  }

  return true;
}

}  // namespace call_trace::service
}  // namespace call_trace
