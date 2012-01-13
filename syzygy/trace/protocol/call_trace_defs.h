// Copyright 2012 Google Inc.
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

#ifndef SYZYGY_TRACE_PROTOCOL_CALL_TRACE_DEFS_H_
#define SYZYGY_TRACE_PROTOCOL_CALL_TRACE_DEFS_H_

#include <windows.h>
#include <wmistr.h>
#include <evntrace.h>  // NOLINT - wmistr must precede envtrace.h

#include "base/basictypes.h"
#include "base/logging.h"

// ID for the call trace provider.
extern const GUID kCallTraceProvider;

// Class of trace provider events.
extern const GUID kCallTraceEventClass;

// GUID for the kernel trace control interface.
extern const GUID kSystemTraceControlGuid;

// This is the absolute minimum number of buffers we will allow, across all
// CPUs.
extern const size_t kMinEtwBuffers;

// This is the minimum number of buffers per CPU we'll allow.
extern const size_t kMinEtwBuffersPerProcessor;

// Max buffers will be min buffers * kEtwBufferMultiplier.
extern const size_t kEtwBufferMultiplier;

// The set of flags to use when logging trace events via ETW.
extern const int kDefaultEtwTraceFlags;

// The set of flags to use when logging kernel events via ETW.
extern const int kDefaultEtwKernelFlags;

// RPC protocol and endpoint.
extern const wchar_t* const kCallTraceRpcProtocol;
extern const wchar_t* const kCallTraceRpcEndpoint;
extern const wchar_t* const kCallTraceRpcMutex;

enum {
  TRACE_VERSION_HI = 1,
  TRACE_VERSION_LO = 0,
};

enum TraceEventType {
  // Header prefix for a "page" of call trace events.
  TRACE_PAGE_HEADER,
  // The actual events are below.
  TRACE_PROCESS_STARTED = 10,
  TRACE_PROCESS_ENDED,
  TRACE_ENTER_EVENT,
  TRACE_EXIT_EVENT,
  TRACE_PROCESS_ATTACH_EVENT,
  TRACE_PROCESS_DETACH_EVENT,
  TRACE_THREAD_ATTACH_EVENT,
  TRACE_THREAD_DETACH_EVENT,
  TRACE_MODULE_EVENT,
  TRACE_BATCH_ENTER,
  TRACE_INVOCATION_BATCH,
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
  // The timestamp of the trace event.
  uint32 timestamp;

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
};

COMPILE_ASSERT(sizeof(RecordPrefix) == 12, record_prefix_size_is_12);

// This structure is written at the beginning of a call trace file.
struct TraceFileHeader {
  // The "magic-number" identifying this as a Syzygy call-trace file.
  // In a valid trace file this will be "SZGY".
  typedef char Signature[4];

  // A canonical value for the signature.
  static const Signature kSignatureValue;

  // A signature is at the start of the trace file header.
  Signature signature;

  // The version of the call trace service which recorded this trace file.
  struct {
    uint16 lo;
    uint16 hi;
  } server_version;

  // The number of bytes in the header. This is the size of this structure
  // plus the length of the command line string (the trailing NUL is already
  // accounted for in the size of this structure).
  uint32 header_size;

  // The block size used when writing the file to disk. The header and
  // all segments are padded and byte aligned to this block size.
  uint32 block_size;

  // The id of the process being traced.
  uint32 process_id;

  // The timestamp (in ticks) when this trace file was created.
  uint32 timestamp;

  // The base address at which the executable module was loaded when the
  // trace file was created.
  uint32 module_base_address;

  // The size of the executable module.
  uint32 module_size;

  // The checksum of the executable module.
  uint32 module_checksum;

  // The timestamp of the executable module.
  uint32 module_time_date_stamp;

  // The path to the executable module.
  wchar_t module_path[MAX_PATH];

  // The number of characters in the command line (not including the trailing
  // NUL character).
  uint32 command_line_len;

  // The command line used to start the traced process.
  wchar_t command_line[1];
};

// Written at the beginning of a call trace file segment. Each call trace file
// segment has a length, which on-disk is rounded up to the block_size, as
// recorded in the TraceFileHeader. Within a call trace segment, there are one
// or more records, each prefixed with a RecordPrefix, which describes the
// length and type of the data to follow.
struct TraceFileSegmentHeader {
  // Type identifiers used for these headers.
  enum { kTypeId = TRACE_PAGE_HEADER };

  // The identity of the thread that is reporting in this segment
  // of the trace file.
  uint32 thread_id;

  // The number of data bytes in this segment of the trace file. This
  // value does not include the size of the record prefix nor the size
  // of the segment header.
  uint32 segment_length;
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
  ModuleAddr module_base_addr;
  size_t module_base_size;
  uint32 module_checksum;
  uint32 module_time_date_stamp;
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

// This is the data recorded for each distinct caller/function
// pair by the profiler.
struct InvocationInfo {
  RetAddr caller;
  FuncAddr function;
  size_t num_calls;
  uint64 cycles_min;
  uint64 cycles_max;
  uint64 cycles_sum;
};

struct InvocationInfoBatch {
  enum { kTypeId = TRACE_INVOCATION_BATCH };

  // TODO(siggi): Perhaps the batch should carry the time resolution for
  //    the invocation data?

  // Back to back entries, as many as our enclosing record's size allows for.
  InvocationInfo invocations[1];
};

#endif  // SYZYGY_TRACE_PROTOCOL_CALL_TRACE_DEFS_H_
