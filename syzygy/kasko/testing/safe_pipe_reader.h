// Copyright 2015 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_KASKO_TESTING_SAFE_PIPE_READER_H_
#define SYZYGY_KASKO_TESTING_SAFE_PIPE_READER_H_

#include <stdint.h>
#include <windows.h>

#include "base/macros.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "base/win/scoped_handle.h"

namespace kasko {
namespace testing {

// Opens an anonymous pipe that may be used for rudimentary IPC.
class SafePipeReader {
 public:
  // Instantiates an anonymous pipe.
  SafePipeReader();

  ~SafePipeReader();

  // @returns an inheritable handle that may be used to write to the pipe.
  HANDLE write_handle() { return write_handle_; }

  // Reads data from the anonymous pipe.
  // @param timeout The maximum duration to wait for the read operation to
  //     complete.
  // @param length The number of bytes to read.
  // @param buffer The destination to read into.
  // @returns true upon success.
  bool ReadData(base::TimeDelta timeout, size_t length, void* buffer);

  // @returns true if the instance is successfully initialized and ready for a
  //     call to ReadData.
  bool IsValid();

 private:
  base::Thread thread_;
  HANDLE read_handle_;
  HANDLE write_handle_;

  DISALLOW_COPY_AND_ASSIGN(SafePipeReader);
};

}  // namespace testing
}  // namespace kasko

#endif  // SYZYGY_KASKO_TESTING_SAFE_PIPE_READER_H_
