// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/sampler/sampled_module_cache.h"

#include "base/bind.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace sampler {

struct MockedCallbackStruct {
  MOCK_METHOD1(OnDeadModule, void(const SampledModuleCache::Module*));
};

class SampledModuleCacheTest : public ::testing::Test {
 public:
  virtual void SetUp() override {
    testing::Test::SetUp();

    dead_module_callback = base::Bind(&MockedCallbackStruct::OnDeadModule,
                                      base::Unretained(&mock));
  }

  bool IsAlive(const SampledModuleCache::Process* process) {
    return process->alive();
  }

  bool IsAlive(const SampledModuleCache::Module* module) {
    return module->alive();
  }

  ::testing::StrictMock<MockedCallbackStruct> mock;
  SampledModuleCache::DeadModuleCallback dead_module_callback;
};

TEST_F(SampledModuleCacheTest, ConstructorAndProperties) {
  SampledModuleCache cache(2);
  EXPECT_EQ(2u, cache.log2_bucket_size());

  EXPECT_TRUE(cache.dead_module_callback().is_null());
  cache.set_dead_module_callback(dead_module_callback);
  EXPECT_FALSE(cache.dead_module_callback().is_null());
}

TEST_F(SampledModuleCacheTest, EmptyCache) {
  SampledModuleCache cache(2);
  cache.RemoveDeadModules();
  EXPECT_TRUE(cache.processes().empty());
}

TEST_F(SampledModuleCacheTest, EndToEnd) {
  SampledModuleCache cache(2);
  cache.set_dead_module_callback(dead_module_callback);
  EXPECT_EQ(0u, cache.processes().size());

  static const DWORD kAccess =
      PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
  base::win::ScopedHandle proc(
      ::OpenProcess(kAccess, FALSE, ::GetCurrentProcessId()));
  ASSERT_TRUE(proc.IsValid());

  SampledModuleCache::ProfilingStatus status =
      SampledModuleCache::kProfilingStarted;
  const SampledModuleCache::Module* module = NULL;

  // Try to add an invalid module. This should fail.
  HMODULE module_handle = ::GetModuleHandle(NULL);
  EXPECT_FALSE(cache.AddModule(
      proc.Get(), module_handle - 1, &status, &module));
  EXPECT_TRUE(module == NULL);
  EXPECT_EQ(0u, cache.processes().size());
  EXPECT_EQ(0u, cache.module_count());

  // Add this module. This should succeed.
  EXPECT_TRUE(cache.AddModule(proc.Get(), module_handle, &status, &module));
  EXPECT_EQ(SampledModuleCache::kProfilingStarted, status);
  EXPECT_TRUE(module != NULL);

  EXPECT_EQ(1u, cache.processes().size());
  const SampledModuleCache::Process* process =
      cache.processes().begin()->second;
  ASSERT_TRUE(process != NULL);
  EXPECT_TRUE(IsAlive(process));

  EXPECT_EQ(1u, cache.processes().begin()->second->modules().size());
  const SampledModuleCache::Module* m = process->modules().begin()->second;
  ASSERT_TRUE(m != NULL);
  EXPECT_TRUE(IsAlive(module));
  EXPECT_EQ(1u, cache.module_count());
  EXPECT_EQ(module, m);

  // Mark the modules as dead.
  cache.MarkAllModulesDead();
  EXPECT_FALSE(IsAlive(process));
  EXPECT_FALSE(IsAlive(module));
  EXPECT_EQ(1u, cache.module_count());

  // Re-add the module. This should simply mark the existing module as alive.
  EXPECT_TRUE(cache.AddModule(proc.Get(), module_handle, &status, &module));
  EXPECT_EQ(SampledModuleCache::kProfilingContinued, status);
  EXPECT_EQ(m, module);

  EXPECT_EQ(1u, cache.processes().size());
  EXPECT_EQ(process, cache.processes().begin()->second);
  EXPECT_TRUE(IsAlive(process));
  EXPECT_EQ(1u, process->modules().size());
  EXPECT_EQ(module, process->modules().begin()->second);
  EXPECT_TRUE(IsAlive(module));
  EXPECT_EQ(1u, cache.module_count());

  // Clean up the modules. Nothing should be removed and the callback should
  // not be invoked.
  cache.RemoveDeadModules();
  EXPECT_EQ(1u, cache.processes().size());
  EXPECT_EQ(process, cache.processes().begin()->second);
  EXPECT_TRUE(IsAlive(process));
  EXPECT_EQ(1u, process->modules().size());
  EXPECT_EQ(module, process->modules().begin()->second);
  EXPECT_TRUE(IsAlive(module));
  EXPECT_EQ(1u, cache.module_count());

  EXPECT_CALL(mock, OnDeadModule(module)).Times(1);

  // Mark everything as dead and clean up the modules. The callback should be
  // invoked and the cache should now be empty.
  cache.MarkAllModulesDead();
  cache.RemoveDeadModules();
  EXPECT_EQ(0u, cache.processes().size());
  EXPECT_EQ(0u, cache.module_count());
}

}  // namespace sampler
