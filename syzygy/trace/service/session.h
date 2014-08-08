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
// This file declares the trace::service::Session class, which manages
// the trace file and buffers for a given client of the call trace service.

#ifndef SYZYGY_TRACE_SERVICE_SESSION_H_
#define SYZYGY_TRACE_SERVICE_SESSION_H_

#include <list>
#include <map>

#include "base/basictypes.h"
#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_ptr.h"
#include "base/process/process.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/win/scoped_handle.h"
#include "syzygy/trace/service/buffer_consumer.h"
#include "syzygy/trace/service/buffer_pool.h"
#include "syzygy/trace/service/process_info.h"

namespace trace {
namespace service {

// Forward declaration.
class Service;

// Holds all of the data associated with a given client session.
// Note that this class it not internally thread safe.  It is expected
// that the CallTraceService will ensure that access to a given instance
// of this class is synchronized.
class Session : public base::RefCountedThreadSafe<Session> {
 public:
  typedef base::ProcessId ProcessId;

  explicit Session(Service* call_trace_service);

 public:
  // Initialize this session object.
  bool Init(ProcessId client_process_id);

  // Close the session. The causes the session to flush all of its outstanding
  // buffers to the write queue.
  bool Close();

  // Get the next available buffer for use by a client. The session retains
  // ownership of the buffer object, it MUST not be deleted by the caller. This
  // may cause new buffers to be allocated if there are no free buffers
  // available.
  // @param buffer will be populated with a pointer to the buffer to be provided
  //     to the client.
  // @returns true on success, false otherwise.
  bool GetNextBuffer(Buffer** buffer);

  // Gets a buffer with a size at least as big as that requested. If the size
  // is consistent with the common buffer pool, this will be satisfied from
  // there. Otherwise, it will result in a specific allocation. The buffer
  // should be returned/recycled in the normal way. Buffers requested in this
  // method are not specifically subject to throttling and thus should only be
  // called for large and long lifespan uses.
  // @param minimum_size the minimum size of the buffer.
  // @param buffer will be populated with a pointer to the buffer to be provided
  //     to the client.
  // @returns true on success, false otherwise.
  bool GetBuffer(size_t minimum_size, Buffer** out_buffer);

  // Returns a full buffer back to the session. After being returned here the
  // session will ensure the buffer gets written to disk before being returned
  // to service.
  // @param buffer the full buffer to return.
  // @returns true on success, false otherwise.
  bool ReturnBuffer(Buffer* buffer);

  // Returns a buffer to the pool of available buffers to be handed out to
  // clients. This is to be called by the write queue thread after the buffer
  // has been written to disk.
  // @param buffer the full buffer to recycle.
  // @returns true on success, false otherwise.
  bool RecycleBuffer(Buffer* buffer);

  // Locates the local record of the given call trace buffer.  The session
  // retains ownership of the buffer object, it MUST not be deleted by the
  // caller.
  bool FindBuffer(::CallTraceBuffer* call_trace_buffer,
                  Buffer** client_buffer);

  // Returns the process id of the client process.
  ProcessId client_process_id() const { return client_.process_id; }

  // Returns the process information about this session's client.
  const ProcessInfo& client_info() const { return client_; }

  // Get the buffer consumer for this session.
  BufferConsumer* buffer_consumer() { return buffer_consumer_; }

  // Set the buffer consumer for this session.
  void set_buffer_consumer(BufferConsumer* consumer) {
    DCHECK(consumer != NULL);
    DCHECK(buffer_consumer_.get() == NULL);
    buffer_consumer_ = consumer;
  }

 protected:
  friend class base::RefCountedThreadSafe<Session>;
  virtual ~Session();

  // @name Testing seams. These are basically events which will be called,
  //     providing places for unittests to set some hooks.
  // @{
  virtual void OnWaitingForBufferToBeRecycled() { }

  virtual void OnDestroySingletonBuffer(Buffer* buffer) { }

  // Initialize process information for @p process_id.
  // @param process_id the process we want to capture information for.
  // @param client the record where we store the captured info.
  // @returns true on success.
  // @note does detailed logging on failure.
  virtual bool InitializeProcessInfo(ProcessId process_id,
                                     ProcessInfo* client);

  // Copy a shared memory segment handle to the client process.
  // @param client_process_handle a valid handle to the client process.
  // @param local_handle the locally valid handle that's to be duplicated.
  // @param client_copy on success returns the copied handle.
  // @returns true on success.
  // @note does detailed logging on failure.
  virtual bool CopyBufferHandleToClient(HANDLE client_process_handle,
                                        HANDLE local_handle,
                                        HANDLE* client_copy);

  // @}

  typedef Buffer::BufferState BufferState;
  typedef std::list<BufferPool*> SharedMemoryBufferCollection;

  // Allocates num_buffers shared client buffers, each of size
  // buffer_size and adds them to the free list.
  // @param num_nuffers the number of buffers to allocate.
  // @param buffer_size the size of each buffer to be allocated.
  // @param pool a pointer to the pool of allocated buffers.
  // @returns true on success, false otherwise.
  // @pre Under lock_.
  bool AllocateBufferPool(
      size_t num_buffers, size_t buffer_size, BufferPool** out_pool);

  // Allocates num_buffers shared client buffers, each of size
  // buffer_size and adds them to the free list.
  // @param num_nuffers the number of buffers to allocate.
  // @param buffer_size the size of each buffer to be allocated.
  // @returns true on success, false otherwise.
  // @pre Under lock_.
  // @note this is virtual to provide a testing seam.
  virtual bool AllocateBuffers(size_t num_buffers, size_t buffer_size);

  // Allocates a buffer for immediate use, not releasing it to the common buffer
  // pool and signaling its availability.
  // @param minimum_size the minimum size of the buffer.
  // @param out_buffer will be set to point to the newly allocated buffer.
  // @pre Under lock_.
  // @pre minimum_size must be bigger than the common buffer allocation size.
  bool AllocateBufferForImmediateUse(size_t minimum_size, Buffer** out_buffer);

  // A private implementation of GetNextBuffer, but which assumes the lock has
  // already been acquired.
  // @param buffer will be populated with a pointer to the buffer to be provided
  //     to the client.
  // @returns true on success, false otherwise.
  // @pre Under lock_.
  bool GetNextBufferUnlocked(Buffer** buffer);

  // Destroys the given buffer, and its containing pool. The buffer must be the
  // only buffer in its pool, and must be in the pending write state. This is
  // meant for destroying singleton buffers that have been allocated with
  // custom sizes. We don't want to return them to the general pool.
  // @param buffer the buffer whose pool is to be destroyed.
  // @returns true on success, false otherwise.
  // @pre buffer is in the 'pending write' state. It should already have been
  //     written but not yet transitioned.
  // @pre buffer is a singleton. That is, is part of a pool that contains only
  //     a single buffer.
  bool DestroySingletonBuffer(Buffer* buffer);

  // Transitions the buffer to the given state. This only updates the buffer's
  // internal state and buffer_state_counts_, but not buffers_available_.
  // DCHECKs on any attempted invalid state changes.
  // @param new_state the new state to be applied to the buffer.
  // @param buffer the buffer to have its state changed.
  // @pre Under lock_.
  void ChangeBufferState(BufferState new_state, Buffer* buffer);

  // Gets (creating if needed) a buffer and populates it with a
  // TRACE_PROCESS_ENDED event. This is called by Close(), which is called
  // when the process owning this session disconnects (at its death).
  // @param buffer receives a pointer to the buffer that is used.
  // @returns true on success, false otherwise.
  // @pre Under lock_.
  bool CreateProcessEndedEvent(Buffer** buffer);

  // Returns true if the buffer book-keeping is self-consistent.
  // @pre Under lock_.
  bool BufferBookkeepingIsConsistent() const;

  // The call trace service this session lives in.  We do not own this
  // object.
  Service* const call_trace_service_;

  // The process information for the client to which the session belongs.
  ProcessInfo client_;

  // All shared memory buffers allocated for this session.
  SharedMemoryBufferCollection shared_memory_buffers_;  // Under lock_.

  // This is the set of buffers that we currently own.
  typedef std::map<Buffer::ID, Buffer*> BufferMap;
  BufferMap buffers_;  // Under lock_.

  // State summary.
  size_t buffer_state_counts_[Buffer::kBufferStateMax];  // Under lock_.

  // The consumer responsible for processing this sessions buffers. The
  // lifetime of this object is managed by the call trace service.
  scoped_refptr<BufferConsumer> buffer_consumer_;

  // Buffers available to give to the clients.
  typedef std::deque<Buffer*> BufferQueue;
  BufferQueue buffers_available_;  // Under lock_.

  // Tracks whether this session is in the process of shutting down.
  bool is_closing_;  // Under lock_.

  // This is used to count the number of GetNextBuffer requests that are
  // currently applying back-pressure. There can only be as many of them as
  // there are buffers to be recycled until we fall below the back-pressure cap.
  size_t buffer_requests_waiting_for_recycle_;  // Under lock_.

  // This condition variable is used to indicate that a buffer is available.
  base::ConditionVariable buffer_is_available_;  // Under lock_.

  // This is currently only used to allocate unique IDs to buffers allocated
  // after the session closes.
  // TODO(rogerm): extend this to all buffers.
  size_t buffer_id_;  // Under lock_.

  // This lock protects any access to the internals related to buffers and their
  // state.
  base::Lock lock_;

  // Tracks whether or not invalid input errors have already been logged.
  // When an error of this type occurs, there will typically be numerous
  // follow-on occurrences that we don't want to log.
  bool input_error_already_logged_;  // Under lock_.

 private:
  DISALLOW_COPY_AND_ASSIGN(Session);
};

}  // namespace service
}  // namespace trace

#endif  // SYZYGY_TRACE_SERVICE_SESSION_H_
