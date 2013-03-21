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
//
// Unit-tests for the jump table count client.

#include "syzygy/agent/jump_table_count/jump_table_count.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace agent {
namespace jump_table_count {

namespace {

const wchar_t kJumpTableCountClientDll[] = L"jump_table_count.dll";

// The test fixture for the jump table count agent.
class JumpTableCountTest : public testing::Test {
 public:
  JumpTableCountTest()
      : agent_module_(NULL) { }

  void LoadDll() {
    ASSERT_EQ(NULL, agent_module_);
    ASSERT_EQ(NULL, jump_table_case_counter_stub_);
    ASSERT_EQ(NULL, ::GetModuleHandle(kJumpTableCountClientDll));

    agent_module_ = ::LoadLibrary(kJumpTableCountClientDll);
    ASSERT_TRUE(agent_module_ != NULL);

    jump_table_case_counter_stub_ =
        ::GetProcAddress(agent_module_, "_jump_table_case_counter");
    ASSERT_TRUE(jump_table_case_counter_stub_ != NULL);

    indirect_penter_dllmain_stub_ =
        ::GetProcAddress(agent_module_, "_indirect_penter_dllmain");
    ASSERT_TRUE(indirect_penter_dllmain_stub_ != NULL);

    indirect_penter_exemain_stub_ =
        ::GetProcAddress(agent_module_, "_indirect_penter_exemain");
    ASSERT_TRUE(indirect_penter_exemain_stub_ != NULL);
  }

  void UnloadDll() {
    if (agent_module_ != NULL) {
      ASSERT_TRUE(::FreeLibrary(agent_module_));
      agent_module_ = NULL;
      jump_table_case_counter_stub_ = NULL;
      indirect_penter_dllmain_stub_ = NULL;
      indirect_penter_exemain_stub_ = NULL;
    }
  }

 protected:
  // The jump table count client module.
  HMODULE agent_module_;

  // The jump table case counter hook.
  static FARPROC jump_table_case_counter_stub_;

  // The DllMain entry stub.
  static FARPROC indirect_penter_dllmain_stub_;

  // The ExeMain entry stub.
  static FARPROC indirect_penter_exemain_stub_;
};

FARPROC JumpTableCountTest::jump_table_case_counter_stub_ = NULL;
FARPROC JumpTableCountTest::indirect_penter_dllmain_stub_ = NULL;
FARPROC JumpTableCountTest::indirect_penter_exemain_stub_ = NULL;

}  // namespace

TEST_F(JumpTableCountTest, LoadUnload) {
  ASSERT_NO_FATAL_FAILURE(LoadDll());
  ASSERT_NO_FATAL_FAILURE(UnloadDll());
}

}  // namespace jump_table_count
}  // namespace agent
