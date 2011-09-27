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

#include "syzygy/call_trace/service.h"

#include "base/command_line.h"
#include "base/file_util.h"
#include "base/scoped_ptr.h"
#include "base/string_util.h"
#include "gtest/gtest.h"
#include "syzygy/call_trace/call_trace_defs.h"
#include "syzygy/call_trace/client_utils.h"
#include "syzygy/call_trace/rpc_helpers.h"

using namespace call_trace::client;
using call_trace::service::Service;

namespace {

class CallTraceServiceTest : public testing::Test {
 public:
  typedef testing::Test Super;

  struct MyRecordType {
    enum { kTypeId = 0xBEEF };
    char message[128];
  };

  CallTraceServiceTest() : client_rpc_binding(NULL) {
  }

  // Sets up each test invocation.
  virtual void SetUp() {
    Super::SetUp();
    ASSERT_TRUE(file_util::CreateNewTempDirectory(L"", &temp_dir));
    client_rpc_binding = 0;
    Service& cts = Service::Instance();
    cts.set_trace_directory(temp_dir);
  }

  // Cleans up after each test invocation.
  virtual void TearDown() {
    if (client_rpc_binding) {
      ASSERT_EQ(RPC_S_OK, RpcBindingFree(&client_rpc_binding));
    }
    Service& cts = Service::Instance();
    cts.Stop();
    file_util::Delete(temp_dir, true);
    Super::TearDown();
  }

  void BindRPC() {
    RPC_WSTR string_binding = NULL;
    std::wstring protocol(Service::kRpcProtocol);
    std::wstring endpoint(Service::kRpcEndpoint);

    ASSERT_TRUE(client_rpc_binding == 0);

    ASSERT_EQ(RPC_S_OK, ::RpcStringBindingCompose(
        NULL, // UUID.
        reinterpret_cast<RPC_WSTR>(&protocol[0]),
        NULL,  // Address.
        reinterpret_cast<RPC_WSTR>(&endpoint[0]),
        NULL, // Options.
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
    CommandLine* cmd_line = CommandLine::ForCurrentProcess();
    RpcStatus status = InvokeRpc(CallTraceClient_CreateSession,
                                 client_rpc_binding,
                                 cmd_line->command_line_string().c_str(),
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
    file_util::FileEnumerator enumerator(temp_dir, false,
                                         file_util::FileEnumerator::FILES,
                                         L"trace-*.bin");
    FilePath trace_file_name(enumerator.Next());
    ASSERT_FALSE(trace_file_name.empty());
    ASSERT_TRUE(enumerator.Next().empty());
    ASSERT_TRUE(file_util::ReadFileToString(trace_file_name, contents));
  }

  void ValidateTraceFileHeader(const TraceFileHeader& header) {
    std::wstring cmd_line(
        CommandLine::ForCurrentProcess()->command_line_string());

    size_t header_size = sizeof(header) + cmd_line.length() * sizeof(wchar_t);

    ASSERT_LT(header.header_size, header.block_size);
    ASSERT_EQ(header.server_version.hi, TRACE_VERSION_HI);
    ASSERT_EQ(header.server_version.lo, TRACE_VERSION_LO);
    ASSERT_EQ(header.header_size, header_size);
    ASSERT_EQ(header.process_id, ::GetCurrentProcessId());
    ASSERT_EQ(header.command_line_len, cmd_line.length() + 1);
    ASSERT_EQ(cmd_line, &header.command_line[0]);
  }

  typedef std::map<HANDLE, uint8*> BasePtrMap;
  BasePtrMap base_ptr_map;
  FilePath temp_dir;
  handle_t client_rpc_binding;
};

} // namespace

TEST_F(CallTraceServiceTest, StartStop) {
  Service& cts = Service::Instance();

  ASSERT_TRUE(cts.Start(true));
  ASSERT_TRUE(cts.Stop());
}

TEST_F(CallTraceServiceTest, Connect) {
  SessionHandle session_handle = NULL;
  TraceFileSegment segment = {};

  Service& cts = Service::Instance();
  ASSERT_TRUE(cts.Start(true));
  CreateSession(&session_handle, &segment);
  ASSERT_TRUE(cts.Stop());

  std::string trace_file_contents;
  ReadTraceFile(&trace_file_contents);

  TraceFileHeader* header =
      reinterpret_cast<TraceFileHeader*>(&trace_file_contents[0]);

  ValidateTraceFileHeader(*header);
  ASSERT_EQ(trace_file_contents.length(), header->block_size);
}

TEST_F(CallTraceServiceTest, Allocate) {
  SessionHandle session_handle = NULL;
  TraceFileSegment segment1 = {};
  TraceFileSegment segment2 = {};

  Service& cts = Service::Instance();
  ASSERT_TRUE(cts.Start(true));

  // Simulate some work on the main thread.
  CreateSession(&session_handle, &segment1);
  WriteSegmentHeader(session_handle, &segment1);
  MyRecordType* record1 = AllocateTraceRecord<MyRecordType>(&segment1);
  base::strlcpy(record1->message, "Message 1", arraysize(record1->message));
  size_t length1 = segment1.header->segment_length;

  // Simulate some work on a second thread.
  AllocateBuffer(session_handle, &segment2);
  WriteSegmentHeader(session_handle, &segment2);
  segment2.header->thread_id += 1;
  MyRecordType* record2 = AllocateTraceRecord<MyRecordType>(&segment2, 256);
  base::strlcpy(record2->message, "Message 2", arraysize(record2->message));
  size_t length2 = segment2.header->segment_length;

  // Commit the buffers in the opposite order.
  ReturnBuffer(session_handle, &segment2);
  CloseSession(&session_handle);

  // Make sure everything is flushed.
  ASSERT_TRUE(cts.Stop());

  std::string trace_file_contents;
  ReadTraceFile(&trace_file_contents);

  TraceFileHeader* header =
      reinterpret_cast<TraceFileHeader*>(&trace_file_contents[0]);

  ValidateTraceFileHeader(*header);
  ASSERT_EQ(trace_file_contents.length(), 3 * header->block_size);

  // Locate and validate the segment header prefix and segment header.
  // This should be segment 2.
  RecordPrefix* prefix = reinterpret_cast<RecordPrefix*>(
      &trace_file_contents[0] + header->block_size);
  ASSERT_EQ(prefix->type, TraceFileSegment::Header::kTypeId);
  ASSERT_EQ(prefix->size, sizeof(TraceFileSegment::Header));
  ASSERT_EQ(prefix->version.hi, TRACE_VERSION_HI);
  ASSERT_EQ(prefix->version.lo, TRACE_VERSION_LO);
  TraceFileSegment::Header* segment_header =
      reinterpret_cast<TraceFileSegment::Header*>(prefix + 1);
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
  prefix = reinterpret_cast<RecordPrefix*>(
      &trace_file_contents[0] + (2 * header->block_size));
  ASSERT_EQ(prefix->type, TraceFileSegment::Header::kTypeId);
  ASSERT_EQ(prefix->size, sizeof(TraceFileSegment::Header));
  ASSERT_EQ(prefix->version.hi, TRACE_VERSION_HI);
  ASSERT_EQ(prefix->version.lo, TRACE_VERSION_LO);
  segment_header = reinterpret_cast<TraceFileSegment::Header*>(prefix + 1);
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
  const char * messages[] = {
      "This is message number 1",
      "The quick brown fox jumped over the lazy dog.",
      "And now for something completely different ...",
  };

  ASSERT_EQ(arraysize(segment_length), num_blocks);
  ASSERT_EQ(arraysize(messages), num_blocks);

  // Start up the service and create a session
  Service& cts = Service::Instance();
  ASSERT_TRUE(cts.Start(true));
  CreateSession(&session_handle, &segment);

  // Write the initial block plus num_blocks "message" blocks.  The n-th block
  // will have n message written to it (i.e., block will have 1 message, the 2nd
  // two, etc)
  for (int block = 0; block < num_blocks; ++block) {
    WriteSegmentHeader(session_handle, &segment);
    for (int i = 0; i <= block; ++i) {
      MyRecordType* record = AllocateTraceRecord<MyRecordType>(&segment);
      base::strlcpy(record->message, messages[i], arraysize(record->message));
    }
    segment_length[block] = segment.header->segment_length;
    ExchangeBuffer(session_handle, &segment);
  }
  ReturnBuffer(session_handle, &segment);
  ASSERT_TRUE(cts.Stop());

  // Load the trace file contents into memory.
  std::string trace_file_contents;
  ReadTraceFile(&trace_file_contents);

  // Read and validate the trace file header. We expect to have written
  // the 1 header block plus num_blocks additional data blocks.
  TraceFileHeader* header =
      reinterpret_cast<TraceFileHeader*>(&trace_file_contents[0]);
  ValidateTraceFileHeader(*header);
  size_t total_blocks = num_blocks + 1;
  ASSERT_EQ(trace_file_contents.length(), total_blocks * header->block_size);

  // Read each data block and validate its contents.
  for (int block = 0; block < num_blocks; ++block) {
    // Locate and validate the segment header prefix.
    RecordPrefix* prefix = reinterpret_cast<RecordPrefix*>(
        &trace_file_contents[0] + ((block + 1) * header->block_size));
    ASSERT_EQ(prefix->type, TraceFileSegment::Header::kTypeId);
    ASSERT_EQ(prefix->size, sizeof(TraceFileSegment::Header));
    ASSERT_EQ(prefix->version.hi, TRACE_VERSION_HI);
    ASSERT_EQ(prefix->version.lo, TRACE_VERSION_LO);

    // The segment header prefix is followed by the actual segment header.
    TraceFileSegment::Header* segment_header =
        reinterpret_cast<TraceFileSegment::Header*>(prefix + 1);
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
  }
}
