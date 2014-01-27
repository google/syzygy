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

#include "syzygy/trace/service/mapped_buffer.h"

#include "syzygy/common/align.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/trace/service/buffer_pool.h"

namespace trace {
namespace service {

// Maps the current buffer. Logs an error message on failure.
// @returns true on success, false otherwise.
bool MappedBuffer::Map() {
  if (data_ != NULL)
    return true;

  BufferPool* pool = buffer_->pool;

  SYSTEM_INFO sys_info = {};
  ::GetSystemInfo(&sys_info);

  DWORD start = buffer_->buffer_offset;
  DWORD end = buffer_->buffer_offset + buffer_->buffer_size;

  // Mapped views of a file have be in chunks that respect the allocation
  // granularity. We choose a view of the file that respects the granularity
  // but also spans the area of interest.
  start = common::AlignDown(start, sys_info.dwAllocationGranularity);

  // Map a view of the shared memory file into this process. We only bring in
  // the portion of the mapping that corresponds to this buffer.
  base_ = reinterpret_cast<uint8*>(
      ::MapViewOfFile(pool->handle(),
                      FILE_MAP_ALL_ACCESS,
                      0,
                      start,
                      end - start));

  if (base_ == NULL) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed mapping buffer: " << ::common::LogWe(error) << ".";
    return false;
  }

  // Grab the offset in the mapping that corresponds to this buffer.
  data_ = base_ + buffer_->buffer_offset - start;

  return true;
}

// Unmaps the current buffer. Logs an error message on failure.
// @returns true on success, false otherwise.
bool MappedBuffer::Unmap() {
  if (data_ == NULL)
    return true;

  BufferPool* pool = buffer_->pool;
  DCHECK(pool->handle() != INVALID_HANDLE_VALUE);

  if (base_ && !::UnmapViewOfFile(base_)) {
    DWORD error = ::GetLastError();
    LOG(WARNING) << "Failed to unmap buffer: " << ::common::LogWe(error) << ".";
    return false;
  }
  base_ = NULL;
  data_ = NULL;

  return true;
}

}  // namespace service
}  // namespace trace
