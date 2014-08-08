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

#include "syzygy/trace/common/unittest_util.h"

#include "base/command_line.h"
#include "base/environment.h"
#include "base/process/kill.h"
#include "base/process/launch.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/win/scoped_handle.h"
#include "syzygy/common/align.h"
#include "syzygy/common/buffer_writer.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace testing {

CallTraceService::CallTraceService()
    : instance_id_(base::StringPrintf("%d", ::GetCurrentProcessId())),
      service_process_(base::kNullProcessHandle) {
}

CallTraceService::~CallTraceService() {
  Stop();
}

void CallTraceService::Start(const base::FilePath& trace_dir) {
  ASSERT_EQ(base::kNullProcessHandle, service_process_);

  CommandLine service_cmd(
      testing::GetExeRelativePath(L"call_trace_service.exe"));
  service_cmd.AppendArg("start");
  service_cmd.AppendSwitch("--verbose");
  service_cmd.AppendSwitchPath("--trace-dir", trace_dir);
  service_cmd.AppendSwitchASCII("--instance-id", instance_id_);

  base::LaunchOptions options;
  options.start_hidden = true;

  std::wstring event_name;
  ::GetSyzygyCallTraceRpcEventName(base::UTF8ToUTF16(instance_id_),
                                   &event_name);
  base::win::ScopedHandle event(
      ::CreateEvent(NULL, TRUE, FALSE, event_name.c_str()));
  ASSERT_TRUE(event.IsValid());

  ASSERT_TRUE(base::LaunchProcess(service_cmd, options, &service_process_));
  ASSERT_NE(base::kNullProcessHandle, service_process_);

  // We wait on both the "ready" handle and the process, as if the process
  // fails for any reason, it'll exit and its handle will become signaled.
  HANDLE handles[] = { event.Get(), service_process_ };
  ASSERT_EQ(WAIT_OBJECT_0, ::WaitForMultipleObjects(arraysize(handles),
                                                    handles,
                                                    FALSE,
                                                    INFINITE));
}

void CallTraceService::Stop() {
  if (service_process_ == base::kNullProcessHandle)
    return;

  CommandLine service_cmd(
      testing::GetExeRelativePath(L"call_trace_service.exe"));
  service_cmd.AppendArg("stop");
  service_cmd.AppendSwitchASCII("--instance-id", instance_id_);

  base::LaunchOptions options;
  options.start_hidden = true;
  options.wait = true;
  ASSERT_TRUE(base::LaunchProcess(service_cmd, options, NULL));

  int exit_code = 0;
  ASSERT_TRUE(base::WaitForExitCode(service_process_, &exit_code));
  service_process_ = base::kNullProcessHandle;
}

void CallTraceService::SetEnvironment() {
  // The instance id needs to be in the environment to be picked up by the
  // client library.
  scoped_ptr<base::Environment> env(base::Environment::Create());
  ASSERT_FALSE(env.get() == NULL);

  // Get the existing value.
  std::string env_var;
  env->GetVar(::kSyzygyRpcInstanceIdEnvVar, &env_var);

  // Prefix the existing environment variable with the instance ID we've
  // chosen. This allows previously intended behaviour to persist.
  env_var.insert(0, ";");
  env_var.insert(0, instance_id_);

  ASSERT_TRUE(env->SetVar(::kSyzygyRpcInstanceIdEnvVar, env_var));
}

void WriteRecord(uint64 timestamp,
                 uint16 record_type,
                 const void* data,
                 size_t length,
                 trace::service::TraceFileWriter* writer) {
  ASSERT_TRUE(data != NULL);
  ASSERT_TRUE(writer != NULL);

  std::vector<uint8> buffer;
  ::common::VectorBufferWriter buffer_writer(&buffer);

  RecordPrefix record = {};
  record.timestamp = timestamp;
  record.type = TraceFileSegmentHeader::kTypeId;
  record.size = sizeof(TraceFileSegmentHeader);
  record.version.hi = TRACE_VERSION_HI;
  record.version.lo = TRACE_VERSION_LO;
  ASSERT_TRUE(buffer_writer.Write(record));

  TraceFileSegmentHeader header = {};
  header.segment_length = sizeof(RecordPrefix) + length;
  header.thread_id = ::GetCurrentThreadId();
  ASSERT_TRUE(buffer_writer.Write(header));

  record.type = record_type;
  record.size = length;
  ASSERT_TRUE(buffer_writer.Write(record));

  ASSERT_TRUE(buffer_writer.Write(
      length, reinterpret_cast<const void*>(data)));

  buffer.resize(::common::AlignUp(buffer.size(), writer->block_size()));
  ASSERT_TRUE(writer->WriteRecord(buffer.data(), buffer.size()));
}

}  // namespace testing
