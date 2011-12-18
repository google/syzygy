// Copyright 2011 Google Inc.
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
// This file implements the call_trace::service::Buffer and BufferPool
// structures, which are used to represent the shared memory buffers
// used by the call_trace service.

#include "syzygy/call_trace/buffer_pool.h"

#include "base/logging.h"
#include "sawbuck/common/com_utils.h"

namespace call_trace {
namespace service {

BufferPool::BufferPool() : base_ptr_(NULL) {
}

BufferPool::~BufferPool() {
  if (base_ptr_ && !::UnmapViewOfFile(base_ptr_)) {
    DWORD error = ::GetLastError();
    DCHECK(handle_.IsValid());
    LOG(WARNING) << "Failed to release buffer: " << com::LogWe(error) << ".";
  }
}

bool BufferPool::Init(Session* session,
                      HANDLE client_process_handle,
                      size_t num_buffers,
                      size_t buffer_size) {
  DCHECK(client_process_handle != NULL);
  DCHECK(num_buffers != 0);
  DCHECK(buffer_size != 0);
  DCHECK(base_ptr_ == NULL);
  DCHECK(!handle_.IsValid());

  size_t mapping_size = num_buffers * buffer_size;

  VLOG(1) << "Creating " << (mapping_size >> 20) << "MB memory pool.";

  // Create a pagefile backed memory mapped file. This will be cut up into a
  // pool of buffers.
  base::win::ScopedHandle new_handle(
      ::CreateFileMapping(NULL, NULL, PAGE_READWRITE, 0, mapping_size, NULL));
  if (!new_handle.IsValid()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to allocate buffer: " << com::LogWe(error) << ".";
    return false;
  }

  // Map a view of the shared memory file into this process.
  uint8* new_base_ptr = reinterpret_cast<uint8*>(
      ::MapViewOfFile(new_handle, FILE_MAP_ALL_ACCESS, 0, 0, mapping_size));
  if (new_base_ptr == NULL) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed mapping buffer: " << com::LogWe(error) << ".";
    return false;
  }

  // Duplicate the mapping handle into the client process.
  HANDLE client_mapping = NULL;
  if (!::DuplicateHandle(::GetCurrentProcess(),
                         new_handle,
                         client_process_handle,
                         &client_mapping,
                         0,
                         FALSE,
                         DUPLICATE_SAME_ACCESS)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to copy shared memory handle into client process: "
               << com::LogWe(error) << ".";
    ignore_result(::UnmapViewOfFile(new_base_ptr));
    return false;
  }

  // Take ownership of the newly created resources.
  handle_.Set(new_handle.Take());
  base_ptr_ = new_base_ptr;

  // Create records for each buffer in the pool.
  buffers_.resize(num_buffers);
  for (size_t i = 0; i < num_buffers; ++i) {
    Buffer& cb = buffers_[i];
    size_t offset = i * buffer_size;
    cb.shared_memory_handle = reinterpret_cast<unsigned long>(client_mapping);
    cb.mapping_size = mapping_size;
    cb.buffer_offset = offset;
    cb.buffer_size = buffer_size;
    cb.session = session;
    cb.data_ptr = base_ptr_ + offset;
    cb.write_is_pending = false;
  }

  return true;
}

}  // namespace call_trace::service
}  // namespace call_trace
