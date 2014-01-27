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
// This file implements the trace::service::Session class, which manages
// the trace file and buffers for a given client of the call trace service.
//
// TODO(rogerm): Reduce the scope over which the session lock is held. The
//     RPC machinery ensures that calls to a given session are serialized, so
//     we only have to protect the parts that might interact with the writer
//     thread.

#include "syzygy/trace/service/session.h"

#include <time.h>

#include "base/command_line.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/memory/scoped_ptr.h"
#include "syzygy/common/align.h"
#include "syzygy/common/buffer_writer.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/path_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/service/mapped_buffer.h"
#include "syzygy/trace/service/service.h"

namespace trace {
namespace service {

namespace {

using base::ProcessId;

// Helper for logging Buffer::ID values.
std::ostream& operator << (std::ostream& stream, const Buffer::ID& buffer_id) {
  return stream << "shared_memory_handle=0x" << std::hex << buffer_id.first
                << ", buffer_offset=0x" << std::hex << buffer_id.second;
}

}  // namespace

Session::Session(Service* call_trace_service)
    : call_trace_service_(call_trace_service),
      is_closing_(false),
      buffer_consumer_(NULL),
      buffer_requests_waiting_for_recycle_(0),
      buffer_is_available_(&lock_),
      buffer_id_(0),
      input_error_already_logged_(false) {
  DCHECK(call_trace_service != NULL);
  ::memset(buffer_state_counts_, 0, sizeof(buffer_state_counts_));

  call_trace_service->AddOneActiveSession();
}

Session::~Session() {
  // We expect all of the buffers to be available, and none of them to be
  // outstanding.
  DCHECK(call_trace_service_ != NULL);
  DCHECK_EQ(buffers_available_.size(),
            buffer_state_counts_[Buffer::kAvailable]);
  DCHECK_EQ(buffers_.size(), buffer_state_counts_[Buffer::kAvailable]);
  DCHECK_EQ(0u, buffer_state_counts_[Buffer::kInUse]);
  DCHECK_EQ(0u, buffer_state_counts_[Buffer::kPendingWrite]);

  // Not strictly necessary, but let's make sure nothing refers to the
  // client buffers before we delete the underlying memory.
  buffers_.clear();
  buffers_available_.clear();

  // The session owns all of its shared memory buffers using raw pointers
  // inserted into the shared_memory_buffers_ list.
  while (!shared_memory_buffers_.empty()) {
    BufferPool* pool = shared_memory_buffers_.back();
    shared_memory_buffers_.pop_back();
    delete pool;
  }

  // TODO(rogerm): Perhaps this code should be tied to the last recycled buffer
  //     after is_closing_ (see RecycleBuffer()). It is bothersome to tie logic
  //     (the services view of the number of active sessions) to the lifetime
  //     of the objects in memory. Arguably, this applies to all of the above
  //     code.
  if (buffer_consumer_ != NULL) {
    buffer_consumer_->Close(this);
    buffer_consumer_ = static_cast<BufferConsumer*>(NULL);
  }

  call_trace_service_->RemoveOneActiveSession();
}

bool Session::Init(ProcessId client_process_id) {
  if (!InitializeProcessInfo(client_process_id, &client_))
    return false;

  return true;
}

bool Session::Close() {
  std::vector<Buffer*> buffers;
  base::AutoLock lock(lock_);

  // It's possible that the service is being stopped just after this session
  // was marked for closure. The service would then attempt to re-close the
  // session. Let's ignore these requests.
  if (is_closing_)
    return true;

  // Otherwise the session is being asked to close for the first time.
  is_closing_ = true;

  // We'll reserve space for the worst case scenario buffer count.
  buffers.reserve(buffer_state_counts_[Buffer::kInUse] + 1);

  // Schedule any outstanding buffers for flushing.
  for (BufferMap::iterator it = buffers_.begin(); it != buffers_.end(); ++it) {
    Buffer* buffer = it->second;
    DCHECK(buffer != NULL);
    if (buffer->state == Buffer::kInUse) {
      ChangeBufferState(Buffer::kPendingWrite, buffer);
      buffer_consumer_->ConsumeBuffer(buffer);
    }
  }

  // Create a process ended event. This causes at least one buffer to be in
  // use to store the process ended event.
  Buffer* buffer = NULL;
  if (CreateProcessEndedEvent(&buffer)) {
    DCHECK(buffer != NULL);
    ChangeBufferState(Buffer::kPendingWrite, buffer);
    buffer_consumer_->ConsumeBuffer(buffer);
  }

  return true;
}

bool Session::FindBuffer(CallTraceBuffer* call_trace_buffer,
                         Buffer** client_buffer) {
  DCHECK(call_trace_buffer != NULL);
  DCHECK(client_buffer != NULL);

  base::AutoLock lock(lock_);

  Buffer::ID buffer_id = Buffer::GetID(*call_trace_buffer);

  BufferMap::iterator iter = buffers_.find(buffer_id);
  if (iter == buffers_.end()) {
    if (!input_error_already_logged_) {
      LOG(ERROR) << "Received call trace buffer not in use for this session "
                 << "[pid=" << client_.process_id << ", " << buffer_id << "].";
      input_error_already_logged_ = true;
    }
    return false;
  }

#ifndef NDEBUG
  // Make sure fields that are not part of the ID also match. The client
  // shouldn't be playing with any of the call_trace_buffer fields.
  if (call_trace_buffer->mapping_size != iter->second->mapping_size ||
      call_trace_buffer->buffer_size != iter->second->buffer_size) {
    LOG(WARNING) << "Received call trace buffer with mismatched attributes.";
  }
#endif

  *client_buffer = iter->second;
  return true;
}

bool Session::GetNextBuffer(Buffer** out_buffer) {
  return GetBuffer(0, out_buffer);
}

bool Session::GetBuffer(size_t minimum_size, Buffer** out_buffer) {
  DCHECK(out_buffer != NULL);

  *out_buffer = NULL;
  base::AutoLock lock(lock_);

  // Once we're closing we should not hand out any more buffers.
  if (is_closing_) {
    LOG(ERROR) << "Session is closing but someone is trying to get a buffer.";
    return false;
  }

  // If this is an ordinary buffer request, delegate to the usual channel.
  if (minimum_size <= call_trace_service_->buffer_size_in_bytes()) {
    if (!GetNextBufferUnlocked(out_buffer))
      return false;
    return true;
  }

  if (!AllocateBufferForImmediateUse(minimum_size, out_buffer))
    return false;

  return true;
}

bool Session::ReturnBuffer(Buffer* buffer) {
  DCHECK(buffer != NULL);
  DCHECK(buffer->session == this);

  {
    base::AutoLock lock(lock_);

    // If we're in the middle of closing, we ignore any ReturnBuffer requests
    // as we've already manually pushed them out for writing.
    if (is_closing_)
      return true;

    ChangeBufferState(Buffer::kPendingWrite, buffer);
  }

  // Hand the buffer over to the consumer.
  if (!buffer_consumer_->ConsumeBuffer(buffer)) {
    LOG(ERROR) << "Unable to schedule buffer for writing.";
    return false;
  }

  return true;
}

bool Session::RecycleBuffer(Buffer* buffer) {
  DCHECK(buffer != NULL);
  DCHECK(buffer->session == this);

  // Is this a special singleton buffer? If so, we don't want to return it to
  // the pool but rather destroy it immediately.
  size_t normal_buffer_size = ::common::AlignUp(
      call_trace_service_->buffer_size_in_bytes(),
      buffer_consumer_->block_size());
  if (buffer->buffer_offset == 0 &&
      buffer->mapping_size == buffer->buffer_size &&
      buffer->buffer_size > normal_buffer_size) {
    if (!DestroySingletonBuffer(buffer))
      return false;
    return true;
  }

  base::AutoLock lock(lock_);

  ChangeBufferState(Buffer::kAvailable, buffer);
  buffers_available_.push_front(buffer);
  buffer_is_available_.Signal();

  // If the session is closing and all outstanding buffers have been recycled
  // then it's safe to destroy this session.
  if (is_closing_ && buffer_state_counts_[Buffer::kInUse] == 0 &&
      buffer_state_counts_[Buffer::kPendingWrite] == 0) {
    // If all buffers have been recycled, then all the buffers we own must be
    // available. When we start closing we refuse to hand out further buffers
    // so this must eventually happen, unless the write queue hangs.
    DCHECK_EQ(buffers_.size(), buffer_state_counts_[Buffer::kAvailable]);
    DCHECK_EQ(buffers_available_.size(),
              buffer_state_counts_[Buffer::kAvailable]);
  }

  return true;
}

void Session::ChangeBufferState(BufferState new_state, Buffer* buffer) {
  DCHECK(buffer != NULL);
  DCHECK(buffer->session == this);
  lock_.AssertAcquired();

  BufferState old_state = buffer->state;

  // Ensure the state transition is valid.
  DCHECK_EQ(static_cast<int>(new_state),
            (static_cast<int>(old_state) + 1) % Buffer::kBufferStateMax);

  // Apply the state change.
  buffer->state = new_state;
  buffer_state_counts_[old_state]--;
  buffer_state_counts_[new_state]++;
}

bool Session::InitializeProcessInfo(ProcessId process_id,
                                    ProcessInfo* client) {
  DCHECK(client != NULL);

  if (!client->Initialize(process_id)) {
    LOG(ERROR) << "Failed to initialize client info for PID=" << process_id
               << ".";
    return false;
  }

  return true;
}

bool Session::CopyBufferHandleToClient(HANDLE client_process_handle,
                                       HANDLE local_handle,
                                       HANDLE* client_copy) {
  DCHECK(client_process_handle != NULL);
  DCHECK(local_handle != NULL);
  DCHECK(client_copy != NULL);

  // Duplicate the mapping handle into the client process.
  if (!::DuplicateHandle(::GetCurrentProcess(),
                         local_handle,
                         client_process_handle,
                         client_copy,
                         0,
                         FALSE,
                         DUPLICATE_SAME_ACCESS)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to copy shared memory handle into client process: "
               << ::common::LogWe(error) << ".";
    return false;
  }

  return true;
}

bool Session::AllocateBufferPool(
    size_t num_buffers, size_t buffer_size, BufferPool** out_pool) {
  DCHECK_GT(num_buffers, 0u);
  DCHECK_GT(buffer_size, 0u);
  DCHECK(out_pool != NULL);
  lock_.AssertAcquired();

  *out_pool = NULL;

  // Allocate the record for the shared memory buffer.
  scoped_ptr<BufferPool> pool(new BufferPool());
  if (pool.get() == NULL) {
    LOG(ERROR) << "Failed to allocate shared memory buffer.";
    return false;
  }

  // Initialize the shared buffer pool.
  buffer_size = ::common::AlignUp(buffer_size, buffer_consumer_->block_size());
  if (!pool->Init(this, num_buffers, buffer_size)) {
    LOG(ERROR) << "Failed to initialize shared memory buffer.";
    return false;
  }

  // Copy the buffer pool handle to the client process.
  HANDLE client_handle = NULL;
  if (is_closing_) {
    // If the session is closing, there's no reason to copy the handle to the
    // client, nor is there good reason to believe that'll succeed, as the
    // process may be gone. Instead, to ensure the buffers have unique IDs,
    // we assign them a locally unique identifier in the guise of a handle.
    //
    // HACK: we know that handle values are multiple of four, so to make sure
    //    our IDs don't collide, we make them odd.
    // See http://blogs.msdn.com/b/oldnewthing/archive/2005/01/21/358109.aspx.
    client_handle = reinterpret_cast<HANDLE>((++buffer_id_ * 2) + 1);
  } else {
    if (!CopyBufferHandleToClient(client_.process_handle.Get(),
                                  pool->handle(),
                                  &client_handle)) {
      return false;
    }
  }
  DCHECK(client_handle != NULL);

  pool->SetClientHandle(client_handle);

  // Save the shared memory block so that it's managed by the session.
  shared_memory_buffers_.push_back(pool.get());
  *out_pool = pool.release();

  return true;
}

bool Session::AllocateBuffers(size_t num_buffers, size_t buffer_size) {
  DCHECK_GT(num_buffers, 0u);
  DCHECK_GT(buffer_size, 0u);
  lock_.AssertAcquired();

  BufferPool* pool_ptr = NULL;
  if (!AllocateBufferPool(num_buffers, buffer_size, &pool_ptr)) {
    LOG(ERROR) << "Failed to allocate buffer pool.";
    return false;
  }

  // Put the client buffers into the list of available buffers and update
  // the buffer state information.
  for (Buffer* buf = pool_ptr->begin(); buf != pool_ptr->end(); ++buf) {
    Buffer::ID buffer_id = Buffer::GetID(*buf);

    buf->state = Buffer::kAvailable;
    CHECK(buffers_.insert(std::make_pair(buffer_id, buf)).second);

    buffer_state_counts_[Buffer::kAvailable]++;
    buffers_available_.push_back(buf);
    buffer_is_available_.Signal();
  }

  DCHECK(BufferBookkeepingIsConsistent());

  return true;
}

bool Session::AllocateBufferForImmediateUse(size_t minimum_size,
                                            Buffer** out_buffer) {
  DCHECK_LT(call_trace_service_->buffer_size_in_bytes(), minimum_size);
  DCHECK(out_buffer != NULL);
  lock_.AssertAcquired();

  BufferPool* pool_ptr = NULL;
  if (!AllocateBufferPool(1, minimum_size, &pool_ptr)) {
    LOG(ERROR) << "Failed to allocate buffer pool.";
    return false;
  }

  // Get the buffer.
  DCHECK_EQ(pool_ptr->begin() + 1, pool_ptr->end());
  Buffer* buffer = pool_ptr->begin();
  Buffer::ID buffer_id = Buffer::GetID(*buffer);

  // Update the bookkeeping.
  buffer->state = Buffer::kInUse;
  CHECK(buffers_.insert(std::make_pair(buffer_id, buffer)).second);
  buffer_state_counts_[Buffer::kInUse]++;

  DCHECK(BufferBookkeepingIsConsistent());

  *out_buffer = buffer;

  return true;
}

bool Session::GetNextBufferUnlocked(Buffer** out_buffer) {
  DCHECK(out_buffer != NULL);
  lock_.AssertAcquired();

  *out_buffer = NULL;

  // If we have too many pending writes, let's wait until one of those has
  // been completed and recycle that buffer. This provides some back-pressure
  // on our allocation mechanism.
  //
  // Note that this back-pressure maximum simply reduces the amount of
  // memory that will be used in common scenarios. It is still possible to
  // have unbounded memory growth in two ways:
  //
  // (1) Having an unbounded number of processes, and hence sessions. Each
  //     session creates an initial pool of buffers for itself.
  //
  // (2) Having an unbounded number of threads with outstanding (partially
  //     filled and not returned for writing) buffers. The lack of buffers
  //     pending writes will force further allocations as new threads come
  //     looking for buffers.
  //
  // We have to be careful that we don't pile up arbitrary many threads waiting
  // for a finite number of buffers that will be recycled. Hence, we count the
  // number of requests applying back-pressure.
  while (buffers_available_.empty()) {
    // Figure out how many buffers we can force to be recycled according to our
    // threshold and the number of write-pending buffers.
    size_t buffers_force_recyclable = 0;
    if (buffer_state_counts_[Buffer::kPendingWrite] >
        call_trace_service_->max_buffers_pending_write()) {
      buffers_force_recyclable = buffer_state_counts_[Buffer::kPendingWrite] -
          call_trace_service_->max_buffers_pending_write();
    }

    // If there's still room to do so, wait rather than allocating immediately.
    // This will either force us to wait until a buffer has been written and
    // recycled, or if the request volume is high enough we'll likely be
    // satisfied by an allocation.
    if (buffer_requests_waiting_for_recycle_ < buffers_force_recyclable) {
      ++buffer_requests_waiting_for_recycle_;
      OnWaitingForBufferToBeRecycled();  // Unittest hook.
      buffer_is_available_.Wait();
      --buffer_requests_waiting_for_recycle_;
    } else {
      // Otherwise, force an allocation.
      if (!AllocateBuffers(call_trace_service_->num_incremental_buffers(),
                           call_trace_service_->buffer_size_in_bytes())) {
        return false;
      }
    }
  }
  DCHECK(!buffers_available_.empty());

  Buffer* buffer = buffers_available_.front();
  buffers_available_.pop_front();
  ChangeBufferState(Buffer::kInUse, buffer);

  *out_buffer = buffer;
  return true;
}

bool Session::DestroySingletonBuffer(Buffer* buffer) {
  DCHECK(buffer != NULL);
  DCHECK_EQ(0u, buffer->buffer_offset);
  DCHECK_EQ(buffer->mapping_size, buffer->buffer_size);
  DCHECK_EQ(Buffer::kPendingWrite, buffer->state);

  base::AutoLock lock(lock_);

  // Look for the pool that houses this buffer.
  SharedMemoryBufferCollection::iterator it = shared_memory_buffers_.begin();
  BufferPool* pool = NULL;
  for (; it != shared_memory_buffers_.end(); ++it) {
    pool = *it;
    if (buffer >= pool->begin() && buffer < pool->end())
      break;
  }

  // Didn't find the pool?
  if (it == shared_memory_buffers_.end()) {
    LOG(ERROR) << "Unable to find pool for buffer to be destroyed.";
    return false;
  }

  // If the pool contains more than one buffer, bail.
  if (pool->end() - pool->begin() > 1) {
    LOG(ERROR) << "Trying to destroy a pool that contains more than 1 buffer.";
    return false;
  }

  // Call our testing seam notification.
  OnDestroySingletonBuffer(buffer);

  // Remove the pool from our collection of pools.
  shared_memory_buffers_.erase(it);

  // Remove the buffer from the buffer map.
  CHECK_EQ(1u, buffers_.erase(Buffer::GetID(*buffer)));

  // Remove the buffer from our buffer statistics.
  buffer_state_counts_[Buffer::kPendingWrite]--;
  DCHECK(BufferBookkeepingIsConsistent());

  // Finally, delete the pool. This will clean up the buffer.
  delete pool;

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

  MappedBuffer mapped_buffer(*buffer);
  if (!mapped_buffer.Map())
    return false;

  RecordPrefix* segment_prefix =
      reinterpret_cast<RecordPrefix*>(mapped_buffer.data());
  uint64 timestamp = trace::common::GetTsc();
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

bool Session::BufferBookkeepingIsConsistent() const {
  lock_.AssertAcquired();

  size_t buffer_states_ = buffer_state_counts_[Buffer::kAvailable] +
      buffer_state_counts_[Buffer::kInUse] +
      buffer_state_counts_[Buffer::kPendingWrite];
  if (buffer_states_ != buffers_.size())
    return false;

  if (buffers_available_.size() != buffer_state_counts_[Buffer::kAvailable])
    return false;
  return true;
}

}  // namespace service
}  // namespace trace
