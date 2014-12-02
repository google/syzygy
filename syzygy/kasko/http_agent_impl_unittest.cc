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

#include "syzygy/kasko/http_agent_impl.h"

#include <windows.h>

#include <map>
#include <string>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/process/kill.h"
#include "base/process/launch.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/test_timeouts.h"
#include "base/threading/thread.h"
#include "base/win/scoped_handle.h"
#include "gtest/gtest.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/kasko/upload.h"

namespace kasko {

namespace {

// Writes |size| bytes to |handle| and sets |*unblocked| to true.
// Used as a crude timeout mechanism by ReadData().
void UnblockPipe(HANDLE handle, DWORD size, bool* unblocked) {
  std::string unblock_data(size, '\0');
  // Unblock the ReadFile in LocalTestServer::WaitToStart by writing to the
  // pipe. Make sure the call succeeded, otherwise we are very likely to hang.
  DWORD bytes_written = 0;
  LOG(WARNING) << "Timeout reached; unblocking pipe by writing " << size
               << " bytes";
  CHECK(::WriteFile(handle, unblock_data.data(), size, &bytes_written, NULL));
  CHECK_EQ(size, bytes_written);
  *unblocked = true;
}

// Given a file handle, reads into |buffer| until |bytes_max| bytes
// has been read or an error has been encountered.  Returns
// true if the read was successful.
bool ReadData(HANDLE read_fd, HANDLE write_fd, DWORD bytes_max, uint8* buffer) {
  base::Thread thread("test_server_watcher");
  if (!thread.Start())
    return false;

  // Prepare a timeout in case the server fails to start.
  bool unblocked = false;
  thread.message_loop()->PostDelayedTask(
      FROM_HERE, base::Bind(UnblockPipe, write_fd, bytes_max, &unblocked),
      TestTimeouts::action_max_timeout());

  DWORD bytes_read = 0;
  while (bytes_read < bytes_max) {
    DWORD num_bytes;
    if (!::ReadFile(read_fd, buffer + bytes_read, bytes_max - bytes_read,
                    &num_bytes, NULL)) {
      LOG(ERROR) << "ReadFile failed" << ::common::LogWe();
      return false;
    }
    if (num_bytes <= 0) {
      LOG(ERROR) << "ReadFile returned invalid byte count: " << num_bytes;
      return false;
    }
    bytes_read += num_bytes;
  }

  thread.Stop();
  // If the timeout kicked in, abort.
  if (unblocked) {
    LOG(ERROR) << "Timeout exceeded for ReadData";
    return false;
  }

  return true;
}

// Launches and terminates an external web server implemented in Python.
class TestServer {
 public:
  TestServer();
  ~TestServer();

  // Start the test server and block until it's ready. Returns true on success.
  bool Start();

  // Returns the port that the server is listening on.
  uint16_t port() { return port_; }

 private:
  // Handle of the Python process running the test server.
  base::win::ScopedHandle process_handle_;

  // The TCP port that the Python process is listening on.
  uint16_t port_;

  DISALLOW_COPY_AND_ASSIGN(TestServer);
};

TestServer::TestServer() : port_(0) {
}

TestServer::~TestServer() {
  if (process_handle_) {
    if (!base::WaitForSingleProcess(process_handle_.Get(), base::TimeDelta()))
      base::KillProcess(process_handle_.Get(), 1, true);
  }
}

bool TestServer::Start() {
  // We will open a pipe used by the child process to indicate its chosen port.
  base::win::ScopedHandle read_fd;
  base::win::ScopedHandle write_fd;
  {
    HANDLE child_read = NULL;
    HANDLE child_write = NULL;
    if (!::CreatePipe(&child_read, &child_write, NULL, 0)) {
      LOG(ERROR) << "Failed to create pipe" << ::common::LogWe();
      return false;
    }

    read_fd.Set(child_read);
    write_fd.Set(child_write);
  }

  // Have the child inherit the write half.
  if (!::SetHandleInformation(write_fd.Get(), HANDLE_FLAG_INHERIT,
                              HANDLE_FLAG_INHERIT)) {
    LOG(ERROR) << "Failed to enable pipe inheritance" << ::common::LogWe();
    return false;
  }

  {
    base::CommandLine python_command(
        testing::GetSrcRelativePath(L"third_party/python_26/python.exe"));
    python_command.AppendArgPath(
        testing::GetSrcRelativePath(L"syzygy/kasko/test_server.py"));

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
    python_command.AppendArg(
        "--startup-pipe=" +
        base::IntToString(reinterpret_cast<uintptr_t>(write_fd.Get())));

    base::LaunchOptions launch_options;
    launch_options.inherit_handles = true;
    HANDLE process_handle = NULL;
    if (!base::LaunchProcess(python_command, launch_options, &process_handle)) {
      LOG(ERROR) << "Failed to launch "
                 << python_command.GetCommandLineString();
      return false;
    }
    process_handle_.Set(process_handle);
  }

  if (!ReadData(read_fd.Get(), write_fd.Get(), sizeof(port_),
                reinterpret_cast<uint8*>(&port_))) {
    LOG(ERROR) << "Could not read port";
    return false;
  }

  return true;
}

}  // namespace

TEST(HttpAgentImplTest, SimpleUpload) {
  TestServer server;
  ASSERT_TRUE(server.Start());

  base::string16 url =
      L"http://localhost:" + base::UintToString16(server.port()) + L"/path";
  HttpAgentImpl agent_impl(L"test", L"0.0");
  base::string16 response_body;
  uint16_t response_code = 0;
  ASSERT_TRUE(SendHttpUpload(
      &agent_impl, url, std::map<base::string16, base::string16>(),
      "file_contents", L"file_name", &response_body, &response_code));

  EXPECT_EQ(L"file_name=file_contents\r\n", response_body);
  EXPECT_EQ(200, response_code);
}

}  // namespace kasko
