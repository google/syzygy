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
// This file declares the call_trace::service::Session class, which manages
// the trace file and buffers for a given client of the call trace service.

#ifndef SYZYGY_CALL_TRACE_SESSION_H_
#define SYZYGY_CALL_TRACE_SESSION_H_

#include <list>
#include <map>

#include "base/basictypes.h"
#include "base/file_path.h"
#include "base/scoped_ptr.h"
#include "base/win/scoped_handle.h"
#include "syzygy/call_trace/buffer_pool.h"
#include "syzygy/call_trace/process_info.h"

namespace call_trace {
namespace service {

// Forward declaration.
class Service;

// Used to denote a Win32 process.
typedef DWORD ProcessID;

// Holds all of the data associated with a given client session.
// Note that this class it not internally thread safe.  It is expected
// that the CallTraceService will ensure that access to a given instance
// of this class is synchronized.
class Session {
 public:
  explicit Session(Service* call_trace_service);
  ~Session();

  // Initialize this session object.
  bool Init(const FilePath& trace_directory, ProcessID client_process_id);

  // Close the session, flushing its unwritten buffers to the given queue
  // or notifying the caller that is safe to destroy it.
  bool Close(BufferQueue* flush_queue, bool* can_destroy_now);

  // Returns true if there's an available buffer in the free list.
  bool HasAvailableBuffers() const;

  // Allocates num_buffers shared client buffers, each of size
  // buffer_size and adds them to the free list.
  bool AllocateBuffers(size_t num_buffers, size_t buffer_size);

  // Get the next available buffer for use by a client. The session
  // retains ownership of the buffer object, it MUST not be deleted
  // by the caller.
  bool GetNextBuffer(Buffer** buffer);

  // Return a buffer to the pool so that it can be used again.
  bool RecycleBuffer(Buffer* buffer);

  // Locates the local record of the given call trace buffer.  The session
  // retains ownership of the buffer object, it MUST not be deleted by the
  // caller.
  bool FindBuffer(::CallTraceBuffer* call_trace_buffer,
                  Buffer** client_buffer);

  // Returns the handle to the trace file.
  HANDLE trace_file_handle() { return trace_file_handle_.Get(); }

  // Returns the process id of the client process.
  ProcessID client_process_id() const { return client_.process_id; }

  // Returns the path of the trace file.
  const FilePath& trace_file_path() const { return trace_file_path_; }

  // Returns the block size for this session's trace file.
  size_t block_size() const { return block_size_; }

 private:
  typedef std::list<BufferPool*> SharedMemoryBufferCollection;

  // The call trace service this session lives in.  We do not own this
  // object.
  Service* const call_trace_service_;

  // The process information for the client to which the session belongs.
  ProcessInfo client_;

  // The handle to the trace file to which buffers are committed.
  base::win::ScopedHandle trace_file_handle_;

  // The name of the trace file.
  FilePath trace_file_path_;

  // The block size used when writing to disk. This corresponds to
  // the physical sector size of the disk.
  size_t block_size_;

  // All shared memory buffers allocated for this session.
  SharedMemoryBufferCollection shared_memory_buffers_;

  // Buffers currently given out to clients.
  BufferMap buffers_in_use_;

  // Buffers available to give to the clients.
  BufferQueue buffers_available_;

  // Tracks whether this session is in the process of shutting down.
  bool is_closing_;

  DISALLOW_COPY_AND_ASSIGN(Session);
};

typedef std::map<ProcessID, Session*> SessionMap;

}  // namespace call_trace::service
}  // namespace call_trace

#endif  // SYZYGY_CALL_TRACE_SESSION_H_
