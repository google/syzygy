// Copyright 2012 Google Inc. All Rights Reserved.
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
// Defines some unittest helper functions.

#include "syzygy/common/unittest_util.h"
#include "gtest/gtest.h"

namespace testing {

TEST(CommonUnitTestUtil, ScopedLogLevelSaver) {
  int old_level = logging::GetMinLogLevel();
  int new_level = old_level - 1;

  {
    ScopedLogLevelSaver log_level_saver;
    logging::SetMinLogLevel(new_level);
    ASSERT_EQ(new_level, logging::GetMinLogLevel());
  }

  ASSERT_EQ(old_level, logging::GetMinLogLevel());
}

namespace {

void ScopedEnvironmentVariableTestImpl(bool is_variable_set) {
  const char kVariableName[] = "ScopedEnvironmentVariableTestVarName";
  const char kVariableValue[] = "initial";
  const char kVariableOverrideValue[] = "override";

  std::unique_ptr<base::Environment> env(base::Environment::Create());

  // Ensure the variable isn't set.
  std::string initial_value;
  ASSERT_FALSE(env->GetVar(kVariableName, &initial_value));

  // Set it if necessary.
  if (is_variable_set)
    ASSERT_TRUE(env->SetVar(kVariableName, kVariableValue));

  // Override the variable.
  std::unique_ptr<ScopedEnvironmentVariable> override(
      new ScopedEnvironmentVariable(kVariableName, kVariableOverrideValue));
  std::string retrieved_value;
  ASSERT_TRUE(env->GetVar(kVariableName, &retrieved_value));
  ASSERT_EQ(kVariableOverrideValue, retrieved_value);

  // Delete the override.
  override.reset();
  if (is_variable_set) {
    ASSERT_TRUE(env->GetVar(kVariableName, &retrieved_value));
    ASSERT_EQ(kVariableValue, retrieved_value);
  } else {
    ASSERT_FALSE(env->GetVar(kVariableName, &retrieved_value));
  }
}

}  // namespace

TEST(CommonUnitTestUtil, ScopedEnvironmentVariableNotSetCase) {
  ScopedEnvironmentVariableTestImpl(false);
}

TEST(CommonUnitTestUtil, ScopedEnvironmentVariableSetCase) {
  ScopedEnvironmentVariableTestImpl(true);
}

}  // namespace testing
