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

#include "base/bind.h"
#include "base/command_line.h"
#include "base/test/test_suite.h"
#include "base/test/test_switches.h"
#include "base/test/launcher/unit_test_launcher.h"
#include "syzygy/testing/laa.h"

namespace {

void AddOrSuffixGTestFilter(const char* filter) {
  static const char kGTestFilter[] = "gtest_filter";
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
  std::string s = command_line->GetSwitchValueASCII(kGTestFilter);
  if (s.empty()) {
    s = filter;
  } else {
    s.append(":");
    s.append(filter);
  }

  // Only the last switch matters, so simply add another.
  command_line->AppendSwitchASCII(kGTestFilter, s);
}

}  // namespace

int main(int argc, char** argv) {
  base::TestSuite test_suite(argc, argv);

  // We can't use the value from test_timeouts.h as they require
  // TestTimeouts::Initialize to have been called; this function can only be
  // called once, however, and gtest calls it later on.

#ifdef SYZYGY_UNITTESTS_USE_LONG_TIMEOUT
  // Set the timeout value to five minutes.
  std::string test_timeout_val = "300000";
  base::CommandLine::ForCurrentProcess()->AppendSwitchASCII(
      switches::kTestLauncherTimeout, test_timeout_val);
#endif

  // No retry on failures.
  base::CommandLine::ForCurrentProcess()->AppendSwitchASCII(
      switches::kTestLauncherRetryLimit, "0");

#ifdef SYZYGY_UNITTESTS_CHECK_MEMORY_MODEL
  // Depending on the memory model, eliminate tests that can't run in that
  // memory model.
  if (testing::GetAddressSpaceSize() == 2) {
    AddOrSuffixGTestFilter("-*_4G");
  } else {
    CHECK_EQ(4u, testing::GetAddressSpaceSize());
    AddOrSuffixGTestFilter("-*_2G");
  }
#endif

  // We don't need to update |argc| and |argv|, gtest read the value from
  // base::CommandLine::ForCurrentProcess().
  return base::LaunchUnitTests(
      argc, argv,
      base::Bind(&base::TestSuite::Run, base::Unretained(&test_suite)));
}
