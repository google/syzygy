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

#ifndef SYZYGY_AGENT_ASAN_UNITTEST_UTIL_H_
#define SYZYGY_AGENT_ASAN_UNITTEST_UTIL_H_

#include "base/file_util.h"
#include "base/string_piece.h"
#include "base/files/scoped_temp_dir.h"
#include "gtest/gtest.h"
#include "syzygy/trace/logger/logger.h"
#include "syzygy/trace/logger/logger_rpc_impl.h"

namespace testing {

// A unittest fixture that ensures that an ASAN logger instance is up and
// running for the duration of the test. Output is captured to a file so that
// its contents can be read after the test if necessary.
class TestWithAsanLogger : public testing::Test {
 public:
  TestWithAsanLogger();

  // @name testing::Test overrides.
  // @{
  void SetUp() OVERRIDE;
  void TearDown() OVERRIDE;
  // @}

  // @name Accessors.
  // @{
  const std::wstring& instance_id() const { return instance_id_; }
  const base::FilePath& log_file_path() const { return log_file_path_; }
  const base::FilePath& temp_dir() const { return temp_dir_.path(); }
  // @}

  bool LogContains(const base::StringPiece& message);

  // Delete the temporary file used for the logging and its directory.
  void DeleteTempFileAndDirectory();

 private:
  // The log service instance.
  trace::logger::Logger log_service_;

  // Manages the binding between the RPC stub functions and a log service
  // instance.
  trace::logger::RpcLoggerInstanceManager log_service_instance_;

  // The instance ID used by the running logger instance.
  std::wstring instance_id_;

  // The path to the log file where the the logger instance will write.
  base::FilePath log_file_path_;

  // The open file handle, if any to which the logger instance will write.
  file_util::ScopedFILE log_file_;

  // A temporary directory into which the log file will be written.
  base::ScopedTempDir temp_dir_;

  // The contents of the log. These are read by calling LogContains.
  bool log_contents_read_;
  std::string log_contents_;
};

}  // namespace testing

#endif  // SYZYGY_AGENT_ASAN_UNITTEST_UTIL_H_
