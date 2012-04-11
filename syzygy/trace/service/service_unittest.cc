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

#include "syzygy/trace/service/service.h"

#include <psapi.h>
#include <userenv.h>

#include "base/command_line.h"
#include "base/environment.h"
#include "base/file_util.h"
#include "base/process_util.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/memory/scoped_ptr.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/align.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/trace/client/client_utils.h"
#include "syzygy/trace/parse/parse_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/rpc/rpc_helpers.h"

using namespace trace::client;

namespace trace {
namespace service {

namespace {

using base::ProcessHandle;
using base::TERMINATION_STATUS_STILL_RUNNING;
using base::win::ScopedHandle;
using common::AlignUp;
using trace::parser::ParseEnvironmentStrings;
using trace::parser::ParseTraceFileHeaderBlob;

// Calculates the size of the given header on disk.
size_t RoundedSize(const TraceFileHeader& header) {
  return AlignUp(header.header_size, header.block_size);
}

class ScopedEnvironment {
 public:
  ScopedEnvironment() {
    env_ = ::GetEnvironmentStrings();
    DCHECK(env_ != NULL);
  }

  ~ScopedEnvironment() {
    ::FreeEnvironmentStrings(env_);
  }

  const wchar_t* Get() { return env_; }

 private:
  wchar_t* env_;
};

class CallTraceServiceTest : public testing::Test {
 public:
  typedef testing::Test Super;

  struct MyRecordType {
    enum { kTypeId = 0xBEEF };
    char message[128];
  };

  CallTraceServiceTest()
      : env(base::Environment::Create()),
        instance_id(base::StringPrintf(L"%d", ::GetCurrentProcessId())),
        cts(Service::Instance()),
        client_rpc_binding(NULL) {
  }

  // Sets up each test invocation.
  virtual void SetUp() OVERRIDE {
    Super::SetUp();

    // Set up the trace directory.
    ASSERT_TRUE(file_util::CreateNewTempDirectory(L"", &temp_dir));
    ASSERT_FALSE(temp_dir.empty());
    cts.set_trace_directory(temp_dir);

    // Set up the instance id. We give the test instance a "unique" id so that
    // it does not interfere with any other intances or tests that might be
    // concurrently active on the system.
    ASSERT_FALSE(env.get() == NULL);
    env->SetVar(::kSyzygyRpcInstanceIdEnvVar, WideToUTF8(instance_id));
    cts.set_instance_id(instance_id);
  }

  // Cleans up after each test invocation.
  virtual void TearDown() OVERRIDE {
    if (client_rpc_binding) {
      ASSERT_EQ(RPC_S_OK, RpcBindingFree(&client_rpc_binding));
    }
    cts.Stop();
    file_util::Delete(temp_dir, true);
    Super::TearDown();
  }

  void BindRPC() {
    RPC_WSTR string_binding = NULL;
    std::wstring protocol;
    std::wstring endpoint;

   ::GetSyzygyCallTraceRpcProtocol(&protocol);
   ::GetSyzygyCallTraceRpcEndpoint(instance_id, &endpoint);

    ASSERT_TRUE(client_rpc_binding == 0);

    ASSERT_EQ(RPC_S_OK, ::RpcStringBindingCompose(
        NULL,  // UUID.
        reinterpret_cast<RPC_WSTR>(&protocol[0]),
        NULL,  // Address.
        reinterpret_cast<RPC_WSTR>(&endpoint[0]),
        NULL,  // Options.
        &string_binding));

    ASSERT_EQ(RPC_S_OK, ::RpcBindingFromStringBinding(string_binding,
                                                      &client_rpc_binding));

    ::RpcStringFree(&string_binding);

    ASSERT_TRUE(client_rpc_binding != 0);
  }

  void MapSegmentBuffer(TraceFileSegment* segment) {
    ASSERT_TRUE(segment != NULL);

    HANDLE mem_handle =
        reinterpret_cast<HANDLE>(segment->buffer_info.shared_memory_handle);
    uint8*& base_ptr = base_ptr_map[mem_handle];
    if (base_ptr == NULL) {
      base_ptr = reinterpret_cast<uint8*>(
          ::MapViewOfFile(mem_handle, FILE_MAP_WRITE, 0, 0,
                          segment->buffer_info.mapping_size));
    }
    ASSERT_TRUE(base_ptr != NULL);

    segment->header = NULL; // A real client should write/init the header here.
    segment->write_ptr = base_ptr + segment->buffer_info.buffer_offset;
    segment->end_ptr = segment->write_ptr + segment->buffer_info.buffer_size;
  }

  void CreateSession(SessionHandle* session_handle,
                     TraceFileSegment* segment) {
    ASSERT_TRUE(segment != NULL);
    ZeroMemory(segment, sizeof(*segment));
    BindRPC();

    unsigned long flags;
    RpcStatus status = InvokeRpc(CallTraceClient_CreateSession,
                                 client_rpc_binding,
                                 session_handle,
                                 &segment->buffer_info,
                                 &flags);

    ASSERT_FALSE(status.exception_occurred);
    ASSERT_TRUE(status.result);

    MapSegmentBuffer(segment);
  }

  void AllocateBuffer(SessionHandle session_handle,
                      TraceFileSegment* segment) {
    RpcStatus status = InvokeRpc(CallTraceClient_AllocateBuffer,
                                 session_handle,
                                 &segment->buffer_info);

    ASSERT_FALSE(status.exception_occurred);
    ASSERT_TRUE(status.result);

    MapSegmentBuffer(segment);
  }

  void ExchangeBuffer(SessionHandle session_handle,
                      TraceFileSegment* segment) {
    RpcStatus status = InvokeRpc(CallTraceClient_ExchangeBuffer,
                                 session_handle,
                                 &segment->buffer_info);

    ASSERT_FALSE(status.exception_occurred);
    ASSERT_TRUE(status.result);

    MapSegmentBuffer(segment);
  }

  void ReturnBuffer(SessionHandle session_handle,
                    TraceFileSegment* segment) {
    RpcStatus status = InvokeRpc(CallTraceClient_ReturnBuffer,
                                 session_handle,
                                 &segment->buffer_info);

    ASSERT_FALSE(status.exception_occurred);
    ASSERT_TRUE(status.result);

    CallTraceBuffer zeroes;
    ZeroMemory(&zeroes, sizeof(zeroes));
    ASSERT_EQ(0, ::memcmp(&segment->buffer_info, &zeroes, sizeof(zeroes)));

    segment->write_ptr = NULL;
    segment->end_ptr = NULL;
    segment->header = NULL;
  }

  void CloseSession(SessionHandle* session_handle) {
    RpcStatus status = InvokeRpc(CallTraceClient_CloseSession,
                                 session_handle);

    ASSERT_FALSE(status.exception_occurred);
    ASSERT_TRUE(status.result);

    ASSERT_TRUE(*session_handle == NULL);
  }

  void ReadTraceFile(std::string* contents) {
    file_util::FileEnumerator enumerator(temp_dir,
                                         false,
                                         file_util::FileEnumerator::FILES,
                                         L"trace-*.bin");
    FilePath trace_file_name(enumerator.Next());
    ASSERT_FALSE(trace_file_name.empty());
    ASSERT_TRUE(enumerator.Next().empty());
    ASSERT_TRUE(file_util::ReadFileToString(trace_file_name, contents));
  }

  void ValidateTraceFileHeader(const TraceFileHeader& header) {
    std::wstring cmd_line(::GetCommandLineW());

    wchar_t module_path[MAX_PATH];
    ASSERT_TRUE(::GetModuleFileName(NULL,
                                    &module_path[0],
                                    arraysize(module_path)));

    MODULEINFO module_info;
    ASSERT_TRUE(::GetModuleInformation(::GetCurrentProcess(),
                                       ::GetModuleHandle(NULL),
                                       &module_info,
                                       sizeof(module_info)));

    ScopedEnvironment env;
    TraceEnvironmentStrings env_strings;
    ASSERT_TRUE(ParseEnvironmentStrings(env.Get(), &env_strings));

    // Parse the blob at the end of the header, and make sure its parsable.
    std::wstring blob_module_path;
    std::wstring blob_command_line;
    TraceEnvironmentStrings blob_env_strings;
    ASSERT_TRUE(ParseTraceFileHeaderBlob(header,
                                         &blob_module_path,
                                         &blob_command_line,
                                         &blob_env_strings));

    ASSERT_EQ(header.server_version.hi, TRACE_VERSION_HI);
    ASSERT_EQ(header.server_version.lo, TRACE_VERSION_LO);
    ASSERT_EQ(header.process_id, ::GetCurrentProcessId());
    ASSERT_EQ(header.module_base_address,
              reinterpret_cast<uint32>(module_info.lpBaseOfDll));
    ASSERT_EQ(header.module_size,
              static_cast<uint32>(module_info.SizeOfImage));

    ASSERT_EQ(blob_module_path, std::wstring(module_path));
    ASSERT_EQ(blob_command_line, cmd_line);
    ASSERT_THAT(blob_env_strings, ::testing::ContainerEq(env_strings));
  }

  scoped_ptr<base::Environment> env;
  Service& cts;
  typedef std::map<HANDLE, uint8*> BasePtrMap;
  BasePtrMap base_ptr_map;
  FilePath temp_dir;
  handle_t client_rpc_binding;
  std::wstring instance_id;
};

template<typename T1, typename T2>
inline ptrdiff_t RawPtrDiff(const T1* p1, const T2* p2) {
  const uint8* const u1 = reinterpret_cast<const uint8*>(p1);
  const uint8* const u2 = reinterpret_cast<const uint8*>(p2);
  return u1 - u2;
}

void ControlExternalCallTraceService(const std::string& command,
                                     const std::wstring& instance_id,
                                     ScopedHandle* handle) {
  ASSERT_TRUE(command == "start" || command == "stop");
  ASSERT_FALSE(instance_id.empty());
  ASSERT_FALSE(handle == NULL);

  CommandLine cmd_line(testing::GetExeRelativePath(L"call_trace_service.exe"));
  cmd_line.AppendArg(command);
  cmd_line.AppendSwitchNative("instance-id", instance_id);

  base::LaunchOptions options;
  HANDLE temp_handle = NULL;
  ASSERT_TRUE(base::LaunchProcess(cmd_line, options, &temp_handle));
  handle->Set(temp_handle);
}

void StartExternalCallTraceService(const std::wstring& instance_id,
                                   ScopedHandle* handle) {
  ControlExternalCallTraceService("start", instance_id, handle);
}

void StopExternalCallTraceService(const std::wstring& instance_id,
                                  ScopedHandle* service_handle) {
  ASSERT_FALSE(service_handle == NULL);
  ScopedHandle controller_handle;
  ControlExternalCallTraceService("stop", instance_id, &controller_handle);

  static const int k30Seconds = 30 * 1000;  // In milliseconds.
  int exit_code;
  EXPECT_TRUE(base::WaitForExitCodeWithTimeout(controller_handle.Take(),
                                               &exit_code,
                                               k30Seconds));
  EXPECT_EQ(0, exit_code);

  EXPECT_TRUE(base::WaitForExitCodeWithTimeout(service_handle->Take(),
                                               &exit_code,
                                               k30Seconds));
  EXPECT_EQ(0, exit_code);
}

void CheckIsStillRunning(ProcessHandle handle) {
  ::Sleep(1000);

  int exit_code = 0;
  base::TerminationStatus status = base::GetTerminationStatus(handle,
                                                              &exit_code);

  ASSERT_EQ(TERMINATION_STATUS_STILL_RUNNING, status);
  ASSERT_EQ(WAIT_TIMEOUT, exit_code);
}

} // namespace

TEST_F(CallTraceServiceTest, StartStop) {
  EXPECT_TRUE(cts.Start(true));
  EXPECT_TRUE(cts.Stop());
}

TEST_F(CallTraceServiceTest, IsSingletonPerInstanceId) {
  // Create a new instance id to use for this test.
  std::wstring duplicate_id = instance_id + L"-foo";

  // Start an external service with the new instance id.
  ScopedHandle handle;
  ASSERT_NO_FATAL_FAILURE(StartExternalCallTraceService(duplicate_id, &handle));
  ASSERT_NO_FATAL_FAILURE(CheckIsStillRunning(handle));

  // Create a new local service instance and see if it starts. We use a new
  // instance to pick up the new instance id and to make sure any state in
  // the static service instance doesn't compromise the test.
  Service local_cts;
  local_cts.set_instance_id(duplicate_id);
  EXPECT_FALSE(local_cts.Start(true));
  EXPECT_TRUE(local_cts.Stop());

  // The external instance should still be running.
  CheckIsStillRunning(handle);
  StopExternalCallTraceService(duplicate_id, &handle);
}

TEST_F(CallTraceServiceTest, IsConcurrentWithDifferentInstanceId) {
  // Create new instance ids "bar-1" and "bar-2" to use for the external
  // and internal services in this test.
  std::wstring external_id = instance_id + L"-bar-1";
  std::wstring internal_id = instance_id + L"-bar-2";

  // Start an external service with the external instance id.
  ScopedHandle handle;
  ASSERT_NO_FATAL_FAILURE(StartExternalCallTraceService(external_id, &handle));
  ASSERT_NO_FATAL_FAILURE(CheckIsStillRunning(handle));

  // Create a new local service instance and see if it starts. We use a new
  // instance to pick up the new instance id and to make sure any state in
  // the static service instance doesn't compromise the test.
  Service local_cts;
  local_cts.set_instance_id(internal_id);
  EXPECT_TRUE(local_cts.Start(true));
  EXPECT_TRUE(local_cts.Stop());

  // The external instance should still be running.
  CheckIsStillRunning(handle);
  StopExternalCallTraceService(external_id, &handle);
}

TEST_F(CallTraceServiceTest, Connect) {
  SessionHandle session_handle = NULL;
  TraceFileSegment segment;

  ASSERT_TRUE(cts.Start(true));
  ASSERT_NO_FATAL_FAILURE(CreateSession(&session_handle, &segment));
  ASSERT_TRUE(cts.Stop());

  std::string trace_file_contents;
  ReadTraceFile(&trace_file_contents);

  TraceFileHeader* header =
      reinterpret_cast<TraceFileHeader*>(&trace_file_contents[0]);

  ASSERT_NO_FATAL_FAILURE(ValidateTraceFileHeader(*header));
  ASSERT_EQ(trace_file_contents.length(),
            RoundedSize(*header) + header->block_size);
}

TEST_F(CallTraceServiceTest, Allocate) {
  SessionHandle session_handle = NULL;
  TraceFileSegment segment1;
  TraceFileSegment segment2;

  ASSERT_TRUE(cts.Start(true));

  // Simulate some work on the main thread.
  ASSERT_NO_FATAL_FAILURE(CreateSession(&session_handle, &segment1));
  segment1.WriteSegmentHeader(session_handle);
  MyRecordType* record1 = segment1.AllocateTraceRecord<MyRecordType>();
  base::strlcpy(record1->message, "Message 1", arraysize(record1->message));
  size_t length1 = segment1.header->segment_length;

  // Simulate some work on a second thread.
  ASSERT_NO_FATAL_FAILURE(AllocateBuffer(session_handle, &segment2));
  segment2.WriteSegmentHeader(session_handle);
  segment2.header->thread_id += 1;
  MyRecordType* record2 = segment2.AllocateTraceRecord<MyRecordType>(256);
  base::strlcpy(record2->message, "Message 2", arraysize(record2->message));
  size_t length2 = segment2.header->segment_length;

  // Commit the buffers in the opposite order.
  ASSERT_NO_FATAL_FAILURE(ReturnBuffer(session_handle, &segment2));
  ASSERT_NO_FATAL_FAILURE(CloseSession(&session_handle));

  // Make sure everything is flushed.
  ASSERT_TRUE(cts.Stop());

  std::string trace_file_contents;
  ASSERT_NO_FATAL_FAILURE(ReadTraceFile(&trace_file_contents));

  TraceFileHeader* header =
      reinterpret_cast<TraceFileHeader*>(&trace_file_contents[0]);

  ASSERT_NO_FATAL_FAILURE(ValidateTraceFileHeader(*header));
  ASSERT_EQ(trace_file_contents.length(),
            RoundedSize(*header) + 3 * header->block_size);

  // Locate and validate the segment header prefix and segment header.
  // This should be segment 2.
  size_t offset = AlignUp(header->header_size, header->block_size);
  RecordPrefix* prefix =
      reinterpret_cast<RecordPrefix*>(&trace_file_contents[0] + offset);
  ASSERT_EQ(prefix->type, TraceFileSegmentHeader::kTypeId);
  ASSERT_EQ(prefix->size, sizeof(TraceFileSegmentHeader));
  ASSERT_EQ(prefix->version.hi, TRACE_VERSION_HI);
  ASSERT_EQ(prefix->version.lo, TRACE_VERSION_LO);
  TraceFileSegmentHeader* segment_header =
      reinterpret_cast<TraceFileSegmentHeader*>(prefix + 1);
  ASSERT_EQ(segment_header->segment_length, length2);
  ASSERT_EQ(segment_header->thread_id, 1 + ::GetCurrentThreadId());

  // The segment header is followed by the message prefix and record.
  // This should be message 2.
  prefix = reinterpret_cast<RecordPrefix*>(segment_header + 1);
  ASSERT_EQ(prefix->type, MyRecordType::kTypeId);
  ASSERT_EQ(prefix->size, 256);
  ASSERT_EQ(prefix->version.hi, TRACE_VERSION_HI);
  ASSERT_EQ(prefix->version.lo, TRACE_VERSION_LO);
  MyRecordType* record = reinterpret_cast<MyRecordType*>(prefix + 1);
  ASSERT_STREQ(record->message, "Message 2");

  // Locate and validate the next segment header prefix and segment header.
  // This should be segment 1.

  offset = AlignUp(RawPtrDiff(record + 1, &trace_file_contents[0]),
                   header->block_size);
  prefix = reinterpret_cast<RecordPrefix*>(&trace_file_contents[0] + offset);
  ASSERT_EQ(prefix->type, TraceFileSegmentHeader::kTypeId);
  ASSERT_EQ(prefix->size, sizeof(TraceFileSegmentHeader));
  ASSERT_EQ(prefix->version.hi, TRACE_VERSION_HI);
  ASSERT_EQ(prefix->version.lo, TRACE_VERSION_LO);
  segment_header = reinterpret_cast<TraceFileSegmentHeader*>(prefix + 1);
  ASSERT_EQ(segment_header->segment_length, length1);
  ASSERT_EQ(segment_header->thread_id, ::GetCurrentThreadId());

  // The segment header is followed by the message prefix and record.
  // This should be message 1.
  prefix = reinterpret_cast<RecordPrefix*>(segment_header + 1);
  ASSERT_EQ(prefix->type, MyRecordType::kTypeId);
  ASSERT_EQ(prefix->size, sizeof(MyRecordType));
  ASSERT_EQ(prefix->version.hi, TRACE_VERSION_HI);
  ASSERT_EQ(prefix->version.lo, TRACE_VERSION_LO);
  record = reinterpret_cast<MyRecordType*>(prefix + 1);
  ASSERT_STREQ(record->message, "Message 1");
}

TEST_F(CallTraceServiceTest, SendBuffer) {
  SessionHandle session_handle = NULL;
  TraceFileSegment segment;

  const size_t num_blocks = 3;
  size_t segment_length[] = {0, 0, 0};
  const char* messages[] = {
      "This is message number 1",
      "The quick brown fox jumped over the lazy dog.",
      "And now for something completely different ...",
  };

  ASSERT_EQ(arraysize(segment_length), num_blocks);
  ASSERT_EQ(arraysize(messages), num_blocks);

  // Start up the service and create a session
  ASSERT_TRUE(cts.Start(true));
  ASSERT_NO_FATAL_FAILURE(CreateSession(&session_handle, &segment));

  // Write the initial block plus num_blocks "message" blocks.  The n-th block
  // will have n message written to it (i.e., block will have 1 message, the 2nd
  // two, etc)
  for (int block = 0; block < num_blocks; ++block) {
    segment.WriteSegmentHeader(session_handle);
    for (int i = 0; i <= block; ++i) {
      MyRecordType* record = segment.AllocateTraceRecord<MyRecordType>();
      base::strlcpy(record->message, messages[i], arraysize(record->message));
    }
    segment_length[block] = segment.header->segment_length;
    ASSERT_NO_FATAL_FAILURE(ExchangeBuffer(session_handle, &segment));
  }
  ASSERT_NO_FATAL_FAILURE(ReturnBuffer(session_handle, &segment));
  ASSERT_TRUE(cts.Stop());

  // Load the trace file contents into memory.
  std::string trace_file_contents;
  ASSERT_NO_FATAL_FAILURE(ReadTraceFile(&trace_file_contents));

  // Read and validate the trace file header. We expect to have written
  // the 2 header block plus num_blocks additional data blocks.
  TraceFileHeader* header =
      reinterpret_cast<TraceFileHeader*>(&trace_file_contents[0]);
  ASSERT_NO_FATAL_FAILURE(ValidateTraceFileHeader(*header));
  size_t total_blocks = 1 + num_blocks;
  ASSERT_EQ(trace_file_contents.length(),
            RoundedSize(*header) + total_blocks * header->block_size);

  // Read each data block and validate its contents.
  size_t segment_offset = AlignUp(header->header_size, header->block_size);
  for (int block = 0; block < num_blocks; ++block) {
    // Locate and validate the segment header prefix.
    RecordPrefix* prefix = reinterpret_cast<RecordPrefix*>(
        &trace_file_contents[0] + segment_offset);
    ASSERT_EQ(prefix->type, TraceFileSegmentHeader::kTypeId);
    ASSERT_EQ(prefix->size, sizeof(TraceFileSegmentHeader));
    ASSERT_EQ(prefix->version.hi, TRACE_VERSION_HI);
    ASSERT_EQ(prefix->version.lo, TRACE_VERSION_LO);

    // The segment header prefix is followed by the actual segment header.
    TraceFileSegmentHeader* segment_header =
        reinterpret_cast<TraceFileSegmentHeader*>(prefix + 1);
    ASSERT_EQ(segment_header->segment_length, segment_length[block]);
    ASSERT_EQ(segment_header->thread_id, ::GetCurrentThreadId());

    // The segment header is followed by the n message records, where N
    // is the same as the block number we're currently on (1 based).
    prefix = reinterpret_cast<RecordPrefix*>(segment_header + 1);
    for (int j = 0; j <= block; ++j) {
      ASSERT_EQ(prefix->type, MyRecordType::kTypeId);
      ASSERT_EQ(prefix->size, sizeof(MyRecordType));
      ASSERT_EQ(prefix->version.hi, TRACE_VERSION_HI);
      ASSERT_EQ(prefix->version.lo, TRACE_VERSION_LO);
      MyRecordType* record = reinterpret_cast<MyRecordType*>(prefix + 1);
      ASSERT_STREQ(record->message, messages[j]);
      prefix = reinterpret_cast<RecordPrefix*>(record + 1);
    }

    segment_offset = AlignUp(
        RawPtrDiff(prefix, &trace_file_contents[0]),
        header->block_size);
  }
}

}  // namespace trace::service
}  // namespace trace
