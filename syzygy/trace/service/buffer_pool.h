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
// This file defines the trace::service::Buffer and BufferPool
// structures, which are used to represent the shared memory buffers
// used by the call_trace service.

#ifndef SYZYGY_TRACE_SERVICE_BUFFER_POOL_H_
#define SYZYGY_TRACE_SERVICE_BUFFER_POOL_H_

#include <deque>
#include <map>
#include <utility>
#include <vector>

#include "base/win/scoped_handle.h"
#include "syzygy/trace/rpc/call_trace_rpc.h"

namespace trace {
namespace service {

// Forward declaration.
class BufferPool;
class Session;

// A Buffer extends the RPC defined CallTraceBuffer structure with the
// extra bits needed by the internals of the Call Trace service.
struct Buffer : public ::CallTraceBuffer {
  // A buffer is always in one of the following states.
  enum BufferState {
    kAvailable,
    kInUse,
    kPendingWrite,
    kBufferStateMax,
  };

  // Type used to identify a buffer. The first and second values in the
  // pair are the numeric id of the shared memory handle and the buffer
  // offset, respectively. See the GetID() method, below.
  typedef std::pair<unsigned long, unsigned long> ID;

  // Utility to get the ID for any buffer instance.
  static ID GetID(const CallTraceBuffer& buffer) {
    return std::make_pair(buffer.shared_memory_handle, buffer.buffer_offset);
  }

  // We augment the buffer with some additional state.
  Session* session;
  BufferPool* pool;
  BufferState state;
};

// A BufferPool manages a collection of buffers that all belong to the same
// shared memory allocation.
class BufferPool {
 public:
  BufferPool();
  ~BufferPool();

  // Allocates and maps a shared memory segment sufficiently large for
  // @p num_buffers, each of size @p buffer_size.
  bool Init(Session* session, size_t num_buffers, size_t buffer_size);

  // Updates each buffer in buffers_ with @p client_handle, which should be
  // a copy of handle_, valid in the client process these buffers are to be
  // shared with.
  // @p num_buffers, each of size @p buffer_size.
  void SetClientHandle(HANDLE client_handle);

  Buffer* begin() { return &buffers_[0]; }
  Buffer* end() { return begin() + buffers_.size(); }

  // Returns this pools shared memory segment handle.
  HANDLE handle() const { return handle_.Get(); }

 private:
  typedef std::vector<Buffer> BufferCollection;
  // Sadly ScopedHandle is not const correct.
  mutable base::win::ScopedHandle handle_;
  BufferCollection buffers_;

  DISALLOW_COPY_AND_ASSIGN(BufferPool);
};

}  // namespace service
}  // namespace trace

#endif  // SYZYGY_TRACE_SERVICE_BUFFER_POOL_H_
