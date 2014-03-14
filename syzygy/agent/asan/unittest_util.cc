// Copyright 2013 Google Inc. All Rights Reserved.
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
// Common unittest fixtures and utilities for the ASAN runtime library.

#include "syzygy/agent/asan/unittest_util.h"

#include "base/environment.h"
#include "base/string_number_conversions.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace testing {

const wchar_t kSyzyAsanRtlDll[] = L"syzyasan_rtl.dll";

// Define the function pointers.
#define DEFINE_FUNCTION_PTR_VARIABLE(convention, ret, name, args, argnames)  \
    name##FunctionPtr TestAsanRtl::name##Function;
ASAN_RTL_FUNCTIONS(DEFINE_FUNCTION_PTR_VARIABLE)
#undef DEFINE_FUNCTION_PTR_VARIABLE

// Define versions of all of the functions that expect an error to be thrown by
// the AsanErrorCallback, and in turn raise an exception if the underlying
// function didn't fail.
#define DEFINE_FAILING_FUNCTION(convention, ret, name, args, argnames)  \
  bool name##FunctionFailed args {  \
    __try {  \
      testing::TestAsanRtl::name##Function argnames;  \
    } __except(::GetExceptionCode() == EXCEPTION_ARRAY_BOUNDS_EXCEEDED) {  \
      return true;  \
    }  \
    return false;  \
  }  \
  void testing::TestAsanRtl::name##FunctionFailing args {  \
    ASSERT_TRUE(name##FunctionFailed argnames);  \
  }
ASAN_RTL_FUNCTIONS(DEFINE_FAILING_FUNCTION)
#undef DEFINE_FAILING_FUNCTION

TestWithAsanLogger::TestWithAsanLogger()
    : log_service_instance_(&log_service_), log_contents_read_(false) {
}

void TestWithAsanLogger::SetUp() {
  // Create and open the log file.
  ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  CHECK(file_util::CreateTemporaryFileInDir(temp_dir_.path(), &log_file_path_));
  log_file_.reset(file_util::OpenFile(log_file_path_, "wb"));

  // Configure the environment (to pass the instance id to the agent DLL).
  std::string instance_id;
  scoped_ptr<base::Environment> env(base::Environment::Create());
  env->GetVar(kSyzygyRpcInstanceIdEnvVar, &instance_id);
  instance_id.append(base::StringPrintf(";%ls,%u",
                                        kSyzyAsanRtlDll,
                                        ::GetCurrentProcessId()));
  env->SetVar(kSyzygyRpcInstanceIdEnvVar, instance_id);

  // Configure and start the log service.
  instance_id_ = base::UintToString16(::GetCurrentProcessId());
  log_service_.set_instance_id(instance_id_);
  log_service_.set_destination(log_file_.get());
  log_service_.set_minidump_dir(temp_dir_.path());
  log_service_.set_symbolize_stack_traces(false);
  ASSERT_TRUE(log_service_.Start());

  log_contents_read_ = false;
}

void TestWithAsanLogger::TearDown() {
  log_service_.Stop();
  log_service_.Join();
  log_file_.reset(NULL);
  LogContains("");
}

bool TestWithAsanLogger::LogContains(const base::StringPiece& message) {
  if (!log_contents_read_ && log_file_.get() != NULL) {
    CHECK(file_util::ReadFileToString(log_file_path_, &log_contents_));
    log_contents_read_ = true;
  }
  return log_contents_.find(message.as_string()) != std::string::npos;
}

void TestWithAsanLogger::DeleteTempFileAndDirectory() {
  log_file_.reset();
  if (temp_dir_.IsValid())
    temp_dir_.Delete();
}

void TestWithAsanLogger::ResetLog() {
  DCHECK(log_file_.get() != NULL);
  CHECK(file_util::CreateTemporaryFileInDir(temp_dir_.path(), &log_file_path_));
  file_util::ScopedFILE log_file(file_util::OpenFile(log_file_path_, "wb"));
  log_service_.set_destination(log_file.get());
  log_file_.reset(log_file.release());
  log_contents_read_ = false;
}

}  // namespace testing
