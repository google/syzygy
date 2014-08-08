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

#ifndef SYZYGY_TRACE_PROTOCOL_CALL_TRACE_DEFS_H_
#define SYZYGY_TRACE_PROTOCOL_CALL_TRACE_DEFS_H_

#include <windows.h>
#include <wmistr.h>
#include <evntrace.h>  // NOLINT - wmistr must precede envtrace.h
#include <vector>

#include "base/basictypes.h"
#include "base/strings/string_piece.h"
#include "syzygy/common/assertions.h"
#include "syzygy/trace/common/clock.h"

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
extern const char kSyzygyRpcInstanceIdEnvVar[];
void GetSyzygyCallTraceRpcProtocol(std::wstring* protocol);
void GetSyzygyCallTraceRpcEndpoint(const base::StringPiece16& id,
                                   std::wstring* endpoint);
void GetSyzygyCallTraceRpcMutexName(const base::StringPiece16& id,
                                    std::wstring* mutex_name);
void GetSyzygyCallTraceRpcEventName(const base::StringPiece16& id,
                                    std::wstring* event_name);

// Environment variable used to indicate that an RPC session is mandatory.
extern const char kSyzygyRpcSessionMandatoryEnvVar[];

// This must be bumped anytime the file format is changed.
enum {
  TRACE_VERSION_HI = 1,
  TRACE_VERSION_LO = 4,
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
  TRACE_BATCH_INVOCATION,
  TRACE_THREAD_NAME,
  TRACE_INDEXED_FREQUENCY,
  TRACE_DYNAMIC_SYMBOL,
  TRACE_SAMPLE_DATA,
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
  uint64 timestamp;

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
COMPILE_ASSERT_IS_POD_OF_SIZE(RecordPrefix, 16);

// This structure is written at the beginning of a call trace file. If the
// format of this trace file changes the server version must be increased.
struct TraceFileHeader {
  // Everything in this header up to and including the header_size field should
  // not be changed in order, layout or alignment. This allows the beginning of
  // the header to be read across all trace file versions. If adding a new
  // fixed length field, do so immediately prior to blob_data. If adding a new
  // variable length field, append it to blob data updating the comment below,
  // and both the reading and writing of TraceFileHeader.

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
  // plus the length of the blob.
  uint32 header_size;

  // Nothing above this point in the header can change in order to maintain
  // the ability to parse the basic header with the version number. This by
  // itself doesn't guarantee backwards compatibility, but it does ensure that
  // we can detect trace files generated by older versions of the toolchain.

  // The block size used when writing the file to disk. The header and
  // all segments are padded and byte aligned to this block size.
  uint32 block_size;

  // The id of the process being traced.
  uint32 process_id;

  // The base address at which the executable module was loaded when the
  // trace file was created.
  uint32 module_base_address;

  // The size of the executable module.
  uint32 module_size;

  // The checksum of the executable module.
  uint32 module_checksum;

  // The timestamp of the executable module.
  uint32 module_time_date_stamp;

  // System information.
  OSVERSIONINFOEX os_version_info;
  SYSTEM_INFO system_info;
  MEMORYSTATUSEX memory_status;

  // Clock information. This lets us convert from timestamps (both TSC and
  // ticks) to absolute system times. It also contains a timestamp for the
  // header itself.
  trace::common::ClockInfo clock_info;

  // The header is required to store multiple variable length fields. We do
  // this via a blob mechanism. The header contains a single binary blob at the
  // end, whose length in bytes) is encoded via blob_length.
  //
  // Currently, the header stores the following variable length fields (in
  // the order indicated):
  //
  //   1. The path to the instrumented module, a NULL terminated wide string.
  //   2. The command line for the process, a NULL terminated wide string.
  //   3. The environment string for the process, an array of wide chars
  //      terminated by a double NULL (individual environment variables are
  //      separated by single NULLs).

  // This stores the variable length data, concatenated. This should be pointer
  // aligned so that PODs with alignment constraints embedded in the blob can be
  // read directly from a header loaded into memory.
  uint8 blob_data[1];
};
COMPILE_ASSERT_IS_POD(TraceFileHeader);

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
COMPILE_ASSERT_IS_POD(TraceFileSegmentHeader);

// The structure traced on function entry or exit.
template<int TypeId>
struct TraceEnterExitEventDataTempl {
  enum { kTypeId = TypeId };
  RetAddr retaddr;
  FuncAddr function;
};

typedef TraceEnterExitEventDataTempl<TRACE_ENTER_EVENT> TraceEnterEventData;
typedef TraceEnterExitEventDataTempl<TRACE_EXIT_EVENT> TraceExitEventData;
typedef TraceEnterEventData TraceEnterExitEventData;
COMPILE_ASSERT_IS_POD(TraceEnterEventData);
COMPILE_ASSERT_IS_POD(TraceExitEventData);
COMPILE_ASSERT_IS_POD(TraceEnterExitEventData);

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
COMPILE_ASSERT_IS_POD(TraceModuleData);

// This is for storing environment string information. Each environment string
// consists of a pair of strings, the key and the value. Certain special
// strings have empty keys.
typedef std::vector<std::pair<std::wstring, std::wstring>>
    TraceEnvironmentStrings;

// Describes the system information and environment in which a process is
// running.
struct TraceSystemInfo {
  OSVERSIONINFOEX os_version_info;
  SYSTEM_INFO system_info;
  MEMORYSTATUSEX memory_status;
  trace::common::ClockInfo clock_info;
  TraceEnvironmentStrings environment_strings;
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

  // Back-to-back entry events.
  TraceEnterEventData calls[1];
};
COMPILE_ASSERT_IS_POD(TraceBatchEnterData);

enum InvocationInfoFlags {
  // If this bit is set in InvocationInfo flags, the caller is a dynamic
  // symbol id, and caller_offset is the offset of the return site, relative to
  // the start of the caller's symbol.
  kCallerIsSymbol = 0x01,
  // If this bit is set in InvocationInfo flags, the function is a dynamic
  // symbol id, instead of an address.
  kFunctionIsSymbol = 0x02,
};

// This is the data recorded for each distinct caller/function
// pair by the profiler.
struct InvocationInfo {
  union {
    RetAddr caller;
    uint32 caller_symbol_id;
  };
  union {
    FuncAddr function;
    uint32 function_symbol_id;
  };
  size_t num_calls;
  uint32 flags:8;
  uint32 caller_offset:24;
  uint64 cycles_min;
  uint64 cycles_max;
  uint64 cycles_sum;
};
COMPILE_ASSERT_IS_POD(InvocationInfo);

struct TraceBatchInvocationInfo {
  enum { kTypeId = TRACE_BATCH_INVOCATION };

  // TODO(siggi): Perhaps the batch should carry the time resolution for
  //    the invocation data?

  // Back to back entries, as many as our enclosing record's size allows for.
  InvocationInfo invocations[1];
};
COMPILE_ASSERT_IS_POD(TraceBatchInvocationInfo);

struct TraceThreadNameInfo {
  enum { kTypeId = TRACE_THREAD_NAME };
  // In fact as many as our enclosing record's size allows for,
  // zero terminated.
  char thread_name[1];
};
COMPILE_ASSERT_IS_POD(TraceThreadNameInfo);

struct TraceIndexedFrequencyData {
  enum { kTypeId = TRACE_INDEXED_FREQUENCY };

  // This is used to tie the data to a particular module, which has already
  // been reported via a TraceModuleData struct.
  ModuleAddr module_base_addr;
  size_t module_base_size;
  uint32 module_checksum;
  uint32 module_time_date_stamp;

  // The number of entries being reported. It is up to the instrumentation to
  // output any other metadata that is required to map an index to an address.
  uint32 num_entries;

  // The number of columns for each record. Each column entry has the data sized
  // specified by |frequency_size|.
  uint32 num_columns;

  // The type of data contained in this frequency record. This should be one of
  // the data-types defined in IndexedFrequencyData::DataType.
  uint8 data_type;

  // The size of the frequency reports: 1, 2 or 4 bytes.
  uint8 frequency_size;

  // In fact, there are frequency_size * num_basic_blocks bytes that follow.
  uint8 frequency_data[1];
};
COMPILE_ASSERT_IS_POD(TraceIndexedFrequencyData);

struct TraceDynamicSymbol {
  enum { kTypeId = TRACE_DYNAMIC_SYMBOL };

  // The symbol's ID, unique per process.
  uint32 symbol_id;
  // In fact as many as our enclosing record's size allows for,
  // zero terminated.
  char symbol_name[1];
};
COMPILE_ASSERT_IS_POD(TraceDynamicSymbol);

struct TraceSampleData {
  enum { kTypeId = TRACE_SAMPLE_DATA };

  // This is used to tie the data to a particular module, which has already
  // been reported via a TraceModuleData struct.
  ModuleAddr module_base_addr;
  size_t module_size;
  uint32 module_checksum;
  uint32 module_time_date_stamp;

  // The size of each bucket in the sample data. This will be a power of 2 in
  // size.
  uint32 bucket_size;

  // The beginning of the sampling buckets as an address in the image.
  // This will be aligned with the bucket size.
  ModuleAddr bucket_start;

  // The number of buckets in the sample data.
  uint32 bucket_count;

  // The time when the trace started and ended.
  uint64 sampling_start_time;
  uint64 sampling_end_time;

  // The sampling interval, expressed in clock cycles.
  uint64 sampling_interval;

  // There are actually |bucket_count| buckets that follow.
  uint32 buckets[1];
};
COMPILE_ASSERT_IS_POD(TraceSampleData);

#endif  // SYZYGY_TRACE_PROTOCOL_CALL_TRACE_DEFS_H_
