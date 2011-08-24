// Copyright 2010 Google Inc.
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

#ifndef SYZYGY_CALL_TRACE_CALL_TRACE_DEFS_H_
#define SYZYGY_CALL_TRACE_CALL_TRACE_DEFS_H_

#include <windows.h>
#include <wmistr.h>
#include <evntrace.h>  // NOLINT - wmistr must precede envtrace.h

#include "base/basictypes.h"
#include "base/logging.h"

#include "call_trace_rpc.h"  // NOLINT - Include dir injected by gyp file.

// ID for the call trace provider.
extern const GUID kCallTraceProvider;

// Class of trace provider events.
extern const GUID kCallTraceEventClass;

// RPC protocol and endpoint.
extern const wchar_t* const kCallTraceRpcProtocol;
extern const wchar_t* const kCallTraceRpcEndpoint;

enum {
  TRACE_VERSION_HI = 1,
  TRACE_VERSION_LO = 0,
};

enum TraceEventType {
  // Header prefix for a "page" of call trace events.
  TRACE_PAGE_HEADER,
  // The actual events are below.
  TRACE_ENTER_EVENT = 10,
  TRACE_EXIT_EVENT,
  TRACE_PROCESS_ATTACH_EVENT,
  TRACE_PROCESS_DETACH_EVENT,
  TRACE_THREAD_ATTACH_EVENT,
  TRACE_THREAD_DETACH_EVENT,
  TRACE_MODULE_EVENT,
  TRACE_BATCH_ENTER,
};

// All traces are emitted at this trace level.
const UCHAR CALL_TRACE_LEVEL = TRACE_LEVEL_INFORMATION;

enum TraceEventFlags {
  // Trace function entry.
  TRACE_FLAG_ENTER          = 0x0001,
  // Trace function exit.
  TRACE_FLAG_EXIT           = 0x0002,
  // Capture stack traces on entry and exit.
  TRACE_FLAG_STACK_TRACES   = 0x0004,
  // Trace DLL load/unload events.
  TRACE_FLAG_LOAD_EVENTS    = 0x0008,
  // Trace DLL thread events.
  TRACE_FLAG_THREAD_EVENTS  = 0x0010,
  // Batch entry traces.
  TRACE_FLAG_BATCH_ENTER    = 0x0020,
};

// Max depth of stack trace captured on entry/exit.
const size_t kMaxTraceDepth = 32;

typedef const void* RetAddr;
typedef const void* FuncAddr;
typedef const void* ModuleAddr;
typedef DWORD ArgumentWord;
typedef DWORD RetValueWord;
typedef void* SessionHandle;

// A prefix for each trace record on disk.
struct RecordPrefix {
  // The size of the record, in bytes;
  uint32 size;

  // The type of trace record.  Will be a value from the TraceEventType
  // enumeration.
  uint16 type;

  // If the call trace service aggregates all trace records to a single
  // file, instead of a file per process, then it's possible that a
  // single file could contain traces produced by multiple versions of
  // the client library.
  struct {
    uint8 hi;
    uint8 lo;
  } version;

  // The timestamp of the trace event.
  uint64 timestamp;
};

COMPILE_ASSERT(sizeof(RecordPrefix) == 16, record_prefix_size_is_16);

// This structure is written at the beginning of a call trace file.
struct TraceFileHeader {
  struct {
    uint16 lo;
    uint16 hi;
  } server_version;
  uint32 header_size;
  uint32 process_id;
  uint32 block_size;
  uint32 command_line_len;
  wchar_t command_line[1];
};

// Write this at the beginning of a call trace buffer (prefixed with
// a RecordPrefix) and keep its buffer_size value up to date as you
// write data into it.
struct TraceFileSegment {
  struct Header {
    // Type identifiers used for these headers.
    enum { kTypeId = TRACE_PAGE_HEADER };

    // The resolution of the timer values recorded in this segment
    // of the trace file.
    uint64 timer_resolution;

    // The identity of the thread that is reporting in this segment
    // of the trace file.
    uint32 thread_handle;

    // The number of bytes in this segment of the trace file.
    uint32 segment_length;
  };

  CallTraceBuffer buffer_info;
  Header* header;
  uint8* write_ptr;
  uint8* end_ptr;
};


// The structure traced on function entry or exit.
template<int TypeId>
struct TraceEnterExitEventDataTempl {
  enum { kTypeId = TypeId };
  size_t depth;
  FuncAddr function;
  union {
    ArgumentWord args[4];
    RetValueWord retval;
  };
  size_t num_traces;
  RetAddr traces[kMaxTraceDepth];
};

typedef TraceEnterExitEventDataTempl<TRACE_ENTER_EVENT> TraceEnterEventData;
typedef TraceEnterExitEventDataTempl<TRACE_EXIT_EVENT> TraceExitEventData;

// For backward source compatibilty.
typedef TraceEnterEventData TraceEnterExitEventData;

// The structure written for each loaded module when module event tracing is
// enabled.
struct TraceModuleData {
  enum { kTypeId = TRACE_MODULE_EVENT };
  ModuleAddr module_base_addr;
  size_t module_base_size;
  wchar_t module_name[256];
  wchar_t module_exe[MAX_PATH];
};

struct FuncCall {
  union {
    DWORD tick_count;
    DWORD ticks_ago;
  };
  FuncAddr function;
};

// The structure traced for batch entry traces.
struct TraceBatchEnterData {
  enum { kTypeId = TRACE_BATCH_ENTER };

  // The thread ID from which these traces originate. This can differ
  // from the logging thread ID when a process exits, and the exiting
  // thread flushes the trace buffers from its expired brethren.
  DWORD thread_id;

  // Number of function entries.
  size_t num_calls;

  // Back-to-back function calls, one for each entry.
  FuncCall calls[1];
};

// Helper funciton round up a value to a given alignment.
inline size_t AlignUp(size_t value, size_t alignment) {
  return ((value + alignment - 1) / alignment) * alignment;
}

// Returns true if there's enough space left in the given segment to write
// num_bytes of data. Note that num_bytes must include the space required
// for both the record and its prefix.
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

#endif  // SYZYGY_CALL_TRACE_CALL_TRACE_DEFS_H_
