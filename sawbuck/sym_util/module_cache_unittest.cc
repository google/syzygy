// Copyright 2009 Google Inc.
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
// Module cache unittests.
#include "sawbuck/sym_util/module_cache.h"
#include "base/at_exit.h"
#include "base/command_line.h"
#include "gtest/gtest.h"

namespace sym_util {

const ProcessId kPid1 = 42;

TEST(ModuleCacheTest, Insert) {
  ModuleCache cache;

  ModuleInformation mod1 = { 0 };
  mod1.image_file_name = L"foo.dll";
  base::Time t0(base::Time::Now());
  cache.ModuleLoaded(kPid1, t0, mod1);

  ModuleInformation mod2 = { 0 };
  mod2.image_file_name = L"bar.dll";
  base::Time t1(t0 + base::TimeDelta::FromMilliseconds(10));
  cache.ModuleLoaded(kPid1, t1, mod2);

  base::Time t2(t1 + base::TimeDelta::FromMilliseconds(10));
  cache.ModuleUnloaded(kPid1, t2, mod1);

  std::vector<ModuleInformation> modules;
  cache.GetProcessModuleState(kPid1, t0, &modules);
  ASSERT_EQ(1, modules.size());
  EXPECT_STREQ(L"foo.dll", modules[0].image_file_name.c_str());

  EXPECT_TRUE(cache.GetProcessModuleState(kPid1, t1, &modules));
  ASSERT_EQ(2, modules.size());
  EXPECT_STREQ(L"foo.dll", modules[0].image_file_name.c_str());
  EXPECT_STREQ(L"bar.dll", modules[1].image_file_name.c_str());

  EXPECT_TRUE(cache.GetProcessModuleState(kPid1, t2, &modules));
  ASSERT_EQ(1, modules.size());
  EXPECT_STREQ(L"bar.dll", modules[0].image_file_name.c_str());

  // Check intermediate time state.
  EXPECT_TRUE(cache.GetProcessModuleState(
      kPid1, t0 + base::TimeDelta::FromMilliseconds(1), &modules));
  ASSERT_EQ(1, modules.size());
  EXPECT_STREQ(L"foo.dll", modules[0].image_file_name.c_str());

  EXPECT_NE(cache.GetStateId(kPid1, t0), cache.GetStateId(kPid1, t1));
  EXPECT_NE(cache.GetStateId(kPid1, t1), cache.GetStateId(kPid1, t2));
  EXPECT_NE(cache.GetStateId(kPid1, t0), cache.GetStateId(kPid1, t2));

  EXPECT_EQ(cache.GetStateId(kPid1, t0), cache.GetStateId(kPid1, t0));
  EXPECT_EQ(cache.GetStateId(kPid1, t1), cache.GetStateId(kPid1, t1));
  EXPECT_EQ(cache.GetStateId(kPid1, t2), cache.GetStateId(kPid1, t2));

  EXPECT_EQ(cache.GetStateId(kPid1, t2),
            cache.GetStateId(kPid1, t2 + base::TimeDelta::FromMilliseconds(1)));
}

}  //  namespace sym_util


int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  CommandLine::Init(argc, argv);
  base::AtExitManager at_exit;

  return RUN_ALL_TESTS();
}
