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

#include "syzygy/kasko/testing/safe_pipe_reader.h"

#include "base/bind.h"
#include "base/location.h"
#include "base/logging.h"

namespace kasko {
namespace testing {
namespace {

// Writes |size| bytes to |handle| and sets |*unblocked| to true.
// Used as a crude timeout mechanism by ReadData().
void UnblockPipe(HANDLE handle, size_t size, bool* unblocked) {
  std::string unblock_data(size, '\0');
  // Unblock the ReadFile in LocalTestServer::WaitToStart by writing to the
  // pipe. Make sure the call succeeded, otherwise we are very likely to hang.
  DWORD bytes_written = 0;
  LOG(WARNING) << "Timeout reached; unblocking pipe by writing " << size
               << " bytes";
  *unblocked = true;
  CHECK(::WriteFile(handle, unblock_data.data(), size, &bytes_written, NULL));
  CHECK_EQ(size, bytes_written);
}

}  // namespace

SafePipeReader::SafePipeReader()
    : thread_("SafePipeReader watcher"),
      write_handle_(INVALID_HANDLE_VALUE),
      read_handle_(INVALID_HANDLE_VALUE) {
  thread_.Start();
  DCHECK(thread_.IsRunning());

  if (thread_.IsRunning()) {
    HANDLE child_read = NULL;
    HANDLE child_write = NULL;
    BOOL result = ::CreatePipe(&child_read, &child_write, NULL, 0);
    DCHECK(result);
    if (result) {
      read_handle_ = child_read;
      write_handle_ = child_write;

      // Make the write half inheritable.
      result = ::SetHandleInformation(write_handle_, HANDLE_FLAG_INHERIT,
                                      HANDLE_FLAG_INHERIT);
      DCHECK(result);
    }
  }
}

SafePipeReader::~SafePipeReader() {
  if (read_handle_ != INVALID_HANDLE_VALUE)
    ::CloseHandle(read_handle_);
  if (write_handle_ != INVALID_HANDLE_VALUE)
    ::CloseHandle(write_handle_);
}

bool SafePipeReader::ReadData(base::TimeDelta timeout,
                              size_t length,
                              void* buffer) {
  size_t bytes_read = 0;
  DCHECK(IsValid());
  if (IsValid()) {
    // Prepare a timeout in case the server fails to start.
    bool unblocked = false;
    thread_.message_loop()->PostDelayedTask(
        FROM_HERE,
        base::Bind(&UnblockPipe, write_handle_, length, &unblocked),
        timeout);

    DWORD num_bytes = 0;
    do {
      num_bytes = 0;
      bool result = ::ReadFile(read_handle_,
                               reinterpret_cast<uint8_t*>(buffer) + bytes_read,
                               length - bytes_read, &num_bytes, NULL);
      DCHECK(result);
      if (result && !unblocked)
        bytes_read += num_bytes;
    } while (num_bytes > 0 && bytes_read < length && !unblocked);
  }

  return bytes_read == length;
}

bool SafePipeReader::IsValid() {
  return read_handle_ != INVALID_HANDLE_VALUE &&
         write_handle_ != INVALID_HANDLE_VALUE && thread_.IsRunning();
}

}  // namespace testing
}  // namespace kasko
