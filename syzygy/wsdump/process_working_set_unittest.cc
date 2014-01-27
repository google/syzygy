// Copyright 2011 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "syzygy/wsdump/process_working_set.h"

#include <psapi.h>
#include <set>
#include <vector>

#include "base/at_exit.h"
#include "base/string_util.h"
#include "base/memory/scoped_ptr.h"
#include "base/win/scoped_handle.h"
#include "gtest/gtest.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/core/address_space.h"

namespace wsdump {

class TestingProcessWorkingSet: public ProcessWorkingSet {
 public:
  using ProcessWorkingSet::ScopedWsPtr;
  using ProcessWorkingSet::CaptureWorkingSet;

  using ProcessWorkingSet::ModuleAddressSpace;
  using ProcessWorkingSet::CaptureModules;
};

TEST(ProcessWorkingSetTest, CaptureWorkingSet) {
  TestingProcessWorkingSet::ScopedWsPtr working_set;
  EXPECT_TRUE(TestingProcessWorkingSet::CaptureWorkingSet(::GetCurrentProcess(),
                                                          &working_set));
  EXPECT_TRUE(working_set.get() != NULL);
}

// This function gives us an address in our module.
static void dummy() {
}

TEST(ProcessWorkingSetTest, CaptureModules) {
  typedef TestingProcessWorkingSet::ModuleAddressSpace ModuleAddressSpace;
  ModuleAddressSpace modules;
  EXPECT_TRUE(TestingProcessWorkingSet::CaptureModules(::GetCurrentProcessId(),
                                                       &modules));
  EXPECT_LT(0U, modules.ranges().size());

  ModuleAddressSpace::Range range(reinterpret_cast<size_t>(&dummy), 1);
  EXPECT_TRUE(modules.FindContaining(range) != modules.end());
}

TEST(ProcessWorkingSetTest, Initialize) {
  ProcessWorkingSet ws;
  ASSERT_TRUE(ws.Initialize(::GetCurrentProcessId()));

  // Double-check the accounting.
  std::set<std::wstring> module_names;
  ProcessWorkingSet::Stats total_modules;
  ProcessWorkingSet::ModuleStatsVector::const_iterator it;
  for (it = ws.module_stats().begin(); it != ws.module_stats().end(); ++it) {
    const ProcessWorkingSet::ModuleStats& stats = *it;

    // Each module name must occur precisely once.
    EXPECT_TRUE(module_names.insert(stats.module_name).second);

    total_modules.pages += stats.pages;
    total_modules.shareable_pages += stats.shareable_pages;
    total_modules.shared_pages += stats.shared_pages;
    total_modules.read_only_pages += stats.read_only_pages;
    total_modules.writable_pages += stats.writable_pages;
    total_modules.executable_pages += stats.executable_pages;
  }

  // Our executable should be in the working set.
  std::wstring exe_name;
  ASSERT_TRUE(
      ::GetModuleFileName(NULL, WriteInto(&exe_name, MAX_PATH), MAX_PATH));
  exe_name.resize(wcslen(exe_name.c_str()));

  EXPECT_TRUE(module_names.find(exe_name) != module_names.end());

  // And finally check the tally.
  EXPECT_EQ(ws.total_stats().pages,
            total_modules.pages + ws.non_module_stats().pages);
  EXPECT_EQ(ws.total_stats().shareable_pages,
      total_modules.shareable_pages + ws.non_module_stats().shareable_pages);
  EXPECT_EQ(ws.total_stats().shared_pages,
      total_modules.shared_pages + ws.non_module_stats().shared_pages);
  EXPECT_EQ(ws.total_stats().read_only_pages,
      total_modules.read_only_pages + ws.non_module_stats().read_only_pages);
  EXPECT_EQ(ws.total_stats().writable_pages,
      total_modules.writable_pages + ws.non_module_stats().writable_pages);
  EXPECT_EQ(ws.total_stats().executable_pages,
      total_modules.executable_pages + ws.non_module_stats().executable_pages);
}

}  // namespace wsdump
