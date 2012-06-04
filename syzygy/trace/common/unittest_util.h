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
//
// Declares a unittest helper class.

#ifndef SYZYGY_TRACE_COMMON_UNITTEST_UTIL_H_
#define SYZYGY_TRACE_COMMON_UNITTEST_UTIL_H_

#include "base/file_path.h"
#include "base/process_util.h"
#include "base/string_piece.h"
#include "gtest/gtest.h"

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
  void Start(const FilePath& trace_dir);

  // Stops the service if it's running.
  void Stop();

  // Publishes the instance ID in the process environment.
  void SetEnvironment();

 private:
  std::string instance_id_;

  // The handle to the call trace service process.
  base::ProcessHandle service_process_;
};

}  // namespace testing

#endif  // SYZYGY_TRACE_COMMON_UNITTEST_UTIL_H_
