// Copyright 2012 Google Inc. All Rights Reserved.
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
// This file implements the trace::service::Buffer and BufferPool
// structures, which are used to represent the shared memory buffers
// used by the call_trace service.

#include "syzygy/trace/service/buffer_pool.h"

#include "base/logging.h"
#include "syzygy/common/com_utils.h"

namespace trace {
namespace service {

BufferPool::BufferPool() {
}

BufferPool::~BufferPool() {
}

bool BufferPool::Init(Session* session,
                      size_t num_buffers,
                      size_t buffer_size) {
  DCHECK(num_buffers != 0);
  DCHECK(buffer_size != 0);
  DCHECK(!handle_.IsValid());

  size_t mapping_size = num_buffers * buffer_size;

  VLOG(1) << "Creating " << (mapping_size >> 20) << "MB memory pool.";

  // Create a pagefile backed memory mapped file. This will be cut up into a
  // pool of buffers.
  base::win::ScopedHandle new_handle(
      ::CreateFileMapping(NULL, NULL, PAGE_READWRITE, 0, mapping_size, NULL));
  if (!new_handle.IsValid()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to allocate buffer: " << ::common::LogWe(error)
               << ".";
    return false;
  }

  // Take ownership of the newly created resources.
  handle_.Set(new_handle.Take());

  // Create records for each buffer in the pool.
  buffers_.resize(num_buffers);
  for (size_t i = 0; i < num_buffers; ++i) {
    Buffer& cb = buffers_[i];
    size_t offset = i * buffer_size;
    cb.shared_memory_handle = NULL;
    cb.mapping_size = mapping_size;
    cb.buffer_offset = offset;
    cb.buffer_size = buffer_size;
    cb.session = session;
    cb.pool = this;
    cb.state = Buffer::kAvailable;
  }

  return true;
}

void BufferPool::SetClientHandle(HANDLE client_handle) {
  DCHECK(client_handle != NULL);

  for (size_t i = 0; i < buffers_.size(); ++i) {
    Buffer& cb = buffers_[i];
    DCHECK_EQ(Buffer::kAvailable, cb.state);
    DCHECK(cb.shared_memory_handle == NULL);
    cb.shared_memory_handle = reinterpret_cast<unsigned long>(client_handle);
  }
}

}  // namespace service
}  // namespace trace
