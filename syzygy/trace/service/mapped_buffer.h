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
//
// Declares a utility class for mapping slices of shared files (buffers, from
// the point of view of the call-trace service) into memory.

#ifndef SYZYGY_TRACE_SERVICE_MAPPED_BUFFER_H_
#define SYZYGY_TRACE_SERVICE_MAPPED_BUFFER_H_

#include <stdint.h>

#include "base/logging.h"

namespace trace {
namespace service {

// Forward declare.
struct Buffer;

// A utility class for creating a scoped on demand memory mapped view into a
// shared file. Automatically unmaps the buffer when destroyed.
class MappedBuffer {
 public:
  // Constructor.
  // @param buffer The buffer to be mapped.
  explicit MappedBuffer(Buffer* buffer)
      : buffer_(buffer), base_(NULL), data_(NULL) {
    DCHECK(buffer != NULL);
  }

  ~MappedBuffer() {
    Unmap();
  }

  // Maps the current buffer. Logs an error message on failure.
  // @returns true on success, false otherwise.
  bool Map();

  // Unmaps the current buffer. Logs an error message on failure.
  // @returns true on success, false otherwise.
  bool Unmap();

  // @returns true if the buffer is mapped, false otherwise.
  bool IsMapped() const { return data_ != NULL; }

  // Returns a pointer to the mapped buffer data.
  uint8_t* data() const { return data_; }

 protected:
  Buffer* buffer_;
  uint8_t* base_;
  uint8_t* data_;
};

}  // namespace service
}  // namespace trace

#endif  // SYZYGY_TRACE_SERVICE_MAPPED_BUFFER_H_
