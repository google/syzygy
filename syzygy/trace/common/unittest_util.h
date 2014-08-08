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
// Declares a unittest helper class.

#ifndef SYZYGY_TRACE_COMMON_UNITTEST_UTIL_H_
#define SYZYGY_TRACE_COMMON_UNITTEST_UTIL_H_

#include "base/files/file_path.h"
#include "base/process/launch.h"
#include "base/strings/string_piece.h"
#include "gtest/gtest.h"
#include "syzygy/trace/service/trace_file_writer.h"

namespace testing {

// A utility class to manage an instance of the call trace service process
// for tests.
class CallTraceService {
 public:
  CallTraceService();
  ~CallTraceService();

  // Starts a call trace service instance with an
  // instance ID unique to this process.
  // @param trace_dir the directory where trace files will be created.
  // @note adds failures to the current tests on errors.
  void Start(const base::FilePath& trace_dir);

  // Stops the service if it's running.
  void Stop();

  // Publishes the instance ID in the process environment.
  void SetEnvironment();

 private:
  std::string instance_id_;

  // The handle to the call trace service process.
  base::ProcessHandle service_process_;
};

// Given a raw record, wraps it with a RecordPrefix/TraceFileSegmentHeader/
// RecordPrefix header before pushing it to the provided TraceFileWriter.
// @param timestamp The timestamp to use for the record.
// @param record_type The type of the record.
// @param data The raw data.
// @param length The length of the raw data.
// @param writer The trace file writer to be written to.
void WriteRecord(uint64 timestamp,
                 uint16 record_type,
                 const void* data,
                 size_t length,
                 trace::service::TraceFileWriter* writer);

}  // namespace testing

#endif  // SYZYGY_TRACE_COMMON_UNITTEST_UTIL_H_
