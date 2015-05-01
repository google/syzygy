// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/kasko/testing/test_server.h"

#include <windows.h>

#include <string>
#include "base/command_line.h"
#include "base/logging.h"
#include "base/process/kill.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/test_timeouts.h"
#include "syzygy/kasko/testing/launch_python_process.h"
#include "syzygy/kasko/testing/safe_pipe_reader.h"

namespace kasko {
namespace testing {
namespace {

base::Process LaunchServer(HANDLE socket_write_handle,
                  const base::FilePath& incoming_directory) {
  base::CommandLine args(base::CommandLine::NO_PROGRAM);
  // Pass the handle on the command-line. Although HANDLE is a
  // pointer, truncating it on 64-bit machines is okay. See
  // http://msdn.microsoft.com/en-us/library/aa384203.aspx
  //
  // "64-bit versions of Windows use 32-bit handles for
  // interoperability. When sharing a handle between 32-bit and 64-bit
  // applications, only the lower 32 bits are significant, so it is
  // safe to truncate the handle (when passing it from 64-bit to
  // 32-bit) or sign-extend the handle (when passing it from 32-bit to
  // 64-bit)."
  args.AppendSwitchASCII(
      "--startup-pipe",
      base::IntToString(reinterpret_cast<uintptr_t>(socket_write_handle)));
  args.AppendSwitchPath("--incoming-directory", incoming_directory);

  return LaunchPythonProcess(
      base::FilePath(L"syzygy/kasko/testing/test_server.py"), args);
}

}  // namespace

TestServer::TestServer() : port_(0) {
}

TestServer::~TestServer() {
  if (process_.IsValid()) {
    int exit_code = 0;
    if (!process_.WaitForExitWithTimeout(base::TimeDelta(), &exit_code))
      process_.Terminate(1, true);
  }
}

bool TestServer::Start() {
  bool started = false;
  incoming_directory_.CreateUniqueTempDir();
  DCHECK(incoming_directory_.IsValid());

  if (incoming_directory_.IsValid()) {
    SafePipeReader pipe_reader;
    DCHECK(pipe_reader.IsValid());

    if (pipe_reader.IsValid()) {
      process_ = LaunchServer(pipe_reader.write_handle(),
                              incoming_directory_.path());
      DCHECK(process_.IsValid());

      if (process_.IsValid()) {
        started = pipe_reader.ReadData(TestTimeouts::action_max_timeout(),
                                       sizeof(port_), &port_);
        DCHECK(started);
      }
    }
  }

  return started;
}

}  // namespace testing
}  // namespace kasko
