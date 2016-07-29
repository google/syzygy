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
// Declares utility functions used by the call trace client and its unit
// tests.

#ifndef SYZYGY_TRACE_CLIENT_CLIENT_UTILS_H_
#define SYZYGY_TRACE_CLIENT_CLIENT_UTILS_H_

#include "base/callback.h"
#include "base/files/file_path.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/rpc/call_trace_rpc.h"

namespace trace {
namespace client {

// Forward declaration.
class RpcSession;

// This structure captures everything that a thread needs to know about
// its current call trace buffer, which corresponds to a call trace segment
// on disk. It holds the buffer information given by the call trace service,
// the memory locations this buffer refers to in the client process, and a
// pointer to the segment header within the buffer so that the segment can
// be consistently maintained.
class TraceFileSegment {
 public:
  TraceFileSegment();

  // @returns true if there's enough space left in the given segment to write
  // num_bytes of raw data.
  bool CanAllocateRaw(size_t num_bytes) const;

  // @returns true if there's enough space left in the given segment to write
  // a prefixed record of length num_bytes.
  bool CanAllocate(size_t num_bytes) const;

  // Writes the segment header at the top of a segment, updating the bytes
  // consumed and initializing the segment header structures.
  void WriteSegmentHeader(SessionHandle session_handle);

  // Allocate a variable length trace record. Typically this is used when
  // the record has a fixed set of fields followed by some variable size
  // blob or string.  The size given must exceed the size of the records
  // fixed fields.
  //
  // @returns a pointer to the allocated record, such that you can populate
  //     its values.
  template<typename RecordType>
  inline RecordType* AllocateTraceRecord(size_t size) {
    DCHECK(size >= sizeof(RecordType));
    return reinterpret_cast<RecordType*>(
        AllocateTraceRecordImpl(RecordType::kTypeId, size));
  }

  // Allocate a fixed length trace record.
  //
  // @returns a pointer to the allocated record, such that you can populate
  //     its values.
  template<typename RecordType>
  inline RecordType* AllocateTraceRecord() {
    return AllocateTraceRecord<RecordType>(sizeof(RecordType));
  }

  // @name Testing seam. Used for observing data that is stuffed into a
  // TraceFileSegment.
  // @{
  typedef base::Callback<void(int record_type,
                              size_t record_size,
                              void* record)>
      AllocateTraceRecordCallback;
  AllocateTraceRecordCallback allocate_callback;
  // @}

 // TODO(siggi): Make this private.
 public:
  // Internal implementation of the trace record allocation function.
  void* AllocateTraceRecordImpl(int record_type,
                                uint32_t record_size);

  // The structure used to communicate buffer information between the
  // client and call trace service.
  CallTraceBuffer buffer_info;

  // Points to the segment header within the call trace buffer. This
  // can  be used to update the segment_length after appending new
  // data to the buffer.
  TraceFileSegmentHeader* header;

  // The lower bound of the call trace buffer in the client process.
  uint8_t* base_ptr;

  // The next memory location at which the client should write call
  // trace data.
  uint8_t* write_ptr;

  // The upper bound of the call trace buffer in the client process.
  uint8_t* end_ptr;
};

// Helper function to transform a DllMain reason to a call trace event type.
int ReasonToEventType(DWORD reason);

// Helper function to get pointer to the prefix for any record
// in a trace file segment.
RecordPrefix* GetRecordPrefix(void *record);

// Given an address in memory returns a pointer to the base address of the
// loaded module in which it lies. Logs verbosely on failure.
// @param address_in_module an address in the image.
// @param module_base will receive a pointer to the base address of the image.
// @returns true on success, false otherwise.
bool GetModuleBaseAddress(void* address_in_module, void** module_base);

// Determines the full path associated with a given module in memory. This is
// replicating functionality from base::PathService, but it uses
// GetModuleFileName which grabs the loader lock. This can cause us issues
// thus we use GetMappedFileName instead.
// @param module_base the base address of the module to be queried.
// @param module_path will receive the path of the module, upon success.
// @returns true on success, false otherwise.
bool GetModulePath(void* module_base, base::FilePath* module_path);

// Given the path to a module, determines the RPC instance ID to be used for
// it. This works by looking at the SYZYGY_RPC_INSTANCE_ID environment variable.
// This environment variable contains a semi-colon separated list of instance
// IDs, where each entry may consist of a comma separated module path and
// instance ID pair. The first semi-colon delimited entry that is a singleton
// is used as the instance ID if no path matches are found. Exact path matches
// have higher priority over basename-only path matches. If no match is found
// and no default ID exists (or the environment variable is not specified), then
// the returned instance ID is empty.
//
// For example, consider the following environment variable:
//
//   SYZYGY_RPC_INSTANCE_ID="1;foo.dll,2;C:\dll\foo.dll,3"
//
// If called with the path "C:\src\foo.dll" then the returned instance ID will
// be "2". If called with the path "C:\dll\foo.dll" the returned instance ID
// will be "3". If called with "C:\bar.dll" the returned instance ID will be
// "1".
//
// @param module_path the path to the module for which we wish to find an
//     instance ID. If it is not absolute it will be made so using the current
//     working directory.
// @returns the instance ID.
std::string GetInstanceIdForModule(const base::FilePath& module_path);

// Encapsulates calls to GetModuleBaseAddress, GetModulePath and
// GetInstanceIdForModule.
// @returns the instance ID for the module in which this function is found.
std::string GetInstanceIdForThisModule();

// Given the path to a module, determines whether or not an RPC connection
// is mandatory for it. This works by looking at the
// SYZYGY_RPC_SESSION_MANDATORY environment variable. This consists of a
// semi-colon separated list of paths and values, similar to
// SYZYGY_RPC_INSTANCE_ID as described in GetInstanceIdForModule. Rather than
// an ID, the value is an integer where 0 = False and non-zero = True.
// If the path matching process returns a non-zero value then failure to create
// an RPC session will cause the instrumented process to terminate with an
// error.
//
// @param module_path the path to the module for which we wish to determine if
//     and RPC session is mandatory.
// @returns true if the session is mandatory, false otherwise.
bool IsRpcSessionMandatory(const base::FilePath& module_path);

// Encapsulates calls to GetModuleBaseAddress, GetModulePath and
// IsRpcSessionMandatory.
// @returns true if an RPC session is mandatory for the module in which this
//     function is found.
bool IsRpcSessionMandatoryForThisModule();

// Initializes an RPC session, automatically getting the instance ID and
// determining if the session is mandatory. If the session is mandatory and it
// is unable to be connected this will raise an exception and cause the process
// to abort.
// @param rpc_session the session to initialize.
// @param segment will receive the first allocated segment upon successful
//     initialization.
// @returns true if everything went well, false if anything went wrong and the
//     session is not mandatory.
bool InitializeRpcSession(RpcSession* rpc_session, TraceFileSegment* segment);

}  // namespace client
}  // namespace trace

#endif  // SYZYGY_TRACE_CLIENT_CLIENT_UTILS_H_
