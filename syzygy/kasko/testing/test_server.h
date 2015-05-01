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

#ifndef SYZYGY_KASKO_TESTING_TEST_SERVER_H_
#define SYZYGY_KASKO_TESTING_TEST_SERVER_H_

#include <stdint.h>

#include "base/macros.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/process.h"
#include "base/win/scoped_handle.h"

namespace kasko {
namespace testing {

// Launches and terminates an external web server implemented in Python.
class TestServer {
 public:
  TestServer();
  ~TestServer();

  // Start the test server and block until it's ready. Returns true on success.
  bool Start();

  // Returns the port that the server is listening on.
  uint16_t port() { return port_; }

  // Returns the directory that the test server writes uploaded files to.
  base::FilePath incoming_directory() { return incoming_directory_.path(); }

 private:
  base::ScopedTempDir incoming_directory_;
  // Python process running the test server.
  base::Process process_;

  // The TCP port that the Python process is listening on.
  uint16_t port_;

  DISALLOW_COPY_AND_ASSIGN(TestServer);
};

}  // namespace testing
}  // namespace kasko

#endif  // SYZYGY_KASKO_TESTING_TEST_SERVER_H_
