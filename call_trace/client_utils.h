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

#ifndef SYZYGY_CALL_TRACE_CLIENT_UTILS_H_
#define SYZYGY_CALL_TRACE_CLIENT_UTILS_H_

#include "syzygy/call_trace/call_trace_defs.h"

namespace call_trace {
namespace client {

// Helper function to transform a DllMain reason to a call trace even type.
int ReasonToEventType(DWORD reason);

// Helper function to get pointer to the prefix for the TraceBatchEnterData
// record (there will be only one, at the very front of the buffer) when
// operating in batch mode.
RecordPrefix* GetTraceBatchPrefix(TraceFileSegment* segment);

// Helper function to get pointer to the TraceBatchEnterData record (there
// will be only one, at the very front of the buffer) when operating in batch
// mode.
TraceBatchEnterData* GetTraceBatchHeader(TraceFileSegment* segment);

// Returns true if there's enough space left in the given segment to write
// num_bytes of raw data.
bool CanAllocateRaw(TraceFileSegment* segment, size_t num_bytes);

// Returns true if there's enough space left in the given segment to write
// a prefixed record of length num_bytes.
bool CanAllocate(TraceFileSegment* segment, size_t num_bytes);

// Writes the segment header at the top of a segment, updating the bytes
// consumed and initializing the segment header structures.
void WriteSegmentHeader(SessionHandle session_handle,
                        TraceFileSegment* segment);

// Internal implementation of the trace record allocation function.
void* AllocateTraceRecordImpl(TraceFileSegment* segment,
                              int record_type,
                              size_t record_size);

// Allocate a variable length trace record. Typically this is used when
// the record has a fixed set of fields followed by some variable size
// blob or string.  The size given must exceed the size of the records
// fixed fields.
//
// Returns a pointer to the allocated record, such that you can populate
// its values.
template<typename RecordType>
inline RecordType* AllocateTraceRecord(TraceFileSegment* segment,
                                       size_t size) {
  DCHECK(size >= sizeof(RecordType));
  return reinterpret_cast<RecordType*>(
      AllocateTraceRecordImpl(segment, RecordType::kTypeId, size));
}

// Allocate a fixed length trace record.
//
// Returns a pointer to the allocated record, such that you can populate
// its values.
template<typename RecordType>
inline RecordType* AllocateTraceRecord(TraceFileSegment* segment) {
  return AllocateTraceRecord<RecordType>(segment, sizeof(RecordType));
}

}  // namespace call_trace::client
}  // namespace call_trace

#endif  // SYZYGY_CALL_TRACE_CLIENT_UTILS_H_
