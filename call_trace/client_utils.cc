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
// Declares utility functions used by the call trace client and its unit
// tests.

#include "syzygy/call_trace/client_utils.h"

namespace call_trace {
namespace client {

int ReasonToEventType(DWORD reason) {
  switch (reason) {
    case DLL_PROCESS_ATTACH:
      return TRACE_PROCESS_ATTACH_EVENT;

    case DLL_PROCESS_DETACH:
      return TRACE_PROCESS_DETACH_EVENT;

    case DLL_THREAD_ATTACH:
      return TRACE_THREAD_ATTACH_EVENT;

    case DLL_THREAD_DETACH:
      return TRACE_THREAD_DETACH_EVENT;

    default:
      NOTREACHED() << "Invalid reason: " << reason << ".";
      return -1;
  }
}

RecordPrefix* GetRecordPrefix(void *record) {
  DCHECK(record != NULL);

  return reinterpret_cast<RecordPrefix*>(record) - 1;
}

TraceFileSegment::TraceFileSegment()
    : header(NULL),
      base_ptr(NULL),
      write_ptr(NULL),
      end_ptr(NULL) {
  // Zero the RPC buffer.
  memset(&buffer_info, 0, sizeof(buffer_info));
}

// Returns true if there's enough space left in the given segment to write
// num_bytes of raw data.
bool TraceFileSegment::CanAllocateRaw(size_t num_bytes) const {
  DCHECK(write_ptr != NULL);
  DCHECK(end_ptr != NULL);
  DCHECK(num_bytes != 0);
  return (write_ptr + num_bytes) <= end_ptr;
}

// Returns true if there's enough space left in the given segment to write
// a prefixed record of length num_bytes.
bool TraceFileSegment::CanAllocate(size_t num_bytes) const {
  DCHECK(num_bytes != 0);
  return CanAllocateRaw(num_bytes + sizeof(RecordPrefix));
}

void FillPrefix(RecordPrefix* prefix, int type, size_t size) {
  prefix->size = size;
  prefix->version.hi = TRACE_VERSION_HI;
  prefix->version.lo = TRACE_VERSION_LO;
  prefix->type = static_cast<uint16>(type);
  prefix->timestamp = ::GetTickCount();
}

// Writes the segment header at the top of a segment, updating the bytes
// consumed and initializing the segment header structures.
void TraceFileSegment::WriteSegmentHeader(SessionHandle session_handle) {
  DCHECK(header == NULL);
  DCHECK(write_ptr != NULL);
  DCHECK(CanAllocate(sizeof(TraceFileSegmentHeader)));

  // The trace record allocation will write the record prefix and update
  // the number of bytes consumed within the buffer.

  RecordPrefix* prefix = reinterpret_cast<RecordPrefix*>(write_ptr);
  FillPrefix(prefix,
             TraceFileSegmentHeader::kTypeId,
             sizeof(TraceFileSegmentHeader));

  header = reinterpret_cast<TraceFileSegmentHeader*>(prefix + 1);
  header->thread_id = ::GetCurrentThreadId();
  header->segment_length = 0;

  write_ptr = reinterpret_cast<uint8*>(header + 1);
}

void* TraceFileSegment::AllocateTraceRecordImpl(int record_type,
                                                size_t record_size) {
  DCHECK(header != NULL);
  DCHECK(write_ptr != NULL);
  DCHECK(record_size != 0);

  const size_t total_size = sizeof(RecordPrefix) + record_size;

  DCHECK(CanAllocateRaw(total_size));

  RecordPrefix* prefix = reinterpret_cast<RecordPrefix*>(write_ptr);
  FillPrefix(prefix, record_type, record_size);

  write_ptr += total_size;
  header->segment_length += total_size;

  return prefix + 1;
}

}  // namespace call_trace::client
}  // namespace call_trace
