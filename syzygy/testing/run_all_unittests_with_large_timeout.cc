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
//
// Test launcher that runs all the tests in a test suite with a large timeout.
//
// By default the unittests run with a timeout of 45 seconds, it's not enough
// for some more intensive tests (like the integration tests). This code is
// pretty much a copy-paste of base/test/run_all_unittests.cc, it just add an
// argument line to the process command line to increase the timeout of the
// unittests.

#include "base/at_exit.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/test/test_suite.h"
#include "base/test/test_switches.h"
#include "base/test/launcher/unit_test_launcher.h"

namespace {

class NoAtExitBaseTestSuite : public base::TestSuite {
 public:
  NoAtExitBaseTestSuite(int argc, char** argv)
      : base::TestSuite(argc, argv, false) {
  }
};

int RunTestSuite(int argc, char** argv) {
  return NoAtExitBaseTestSuite(argc, argv).Run();
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  CommandLine::Init(argc, argv);
  // We can't use the value from test_timeouts.h as they require
  // TestTimeouts::Initialize to have been called; this function can only be
  // called once, however, and gtest calls it later on.
  //
  // Set the timeout value to five minutes.
  std::string test_timeout_val = "300000";
  CommandLine::ForCurrentProcess()->AppendSwitchASCII(
      switches::kTestLauncherTimeout, test_timeout_val);
  // We don't need to update |argc| and |argv|, gtest read the value from
  // CommandLine::ForCurrentProcess().
  return base::LaunchUnitTests(argc,
                               argv,
                               base::Bind(&RunTestSuite,
                                          argc,
                                          argv));
}
