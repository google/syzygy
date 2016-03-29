// Copyright 2016 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/reporters/exported_function.h"

#include "base/bind.h"
#include "gtest/gtest.h"

// A dummy export for the unittest to find.
extern "C" int __declspec(dllexport) ExportedFunctionTarget(int i) {
  return i;
}

namespace agent {
namespace asan {
namespace reporters {

using ExportedFunctionType = ExportedFunction<int __cdecl(int), 0>;
const char* ExportedFunctionType::name_ = "ExportedFunctionTarget";

using MissingExportedFunctionType = ExportedFunction<int __cdecl(int), 1>;
const char* MissingExportedFunctionType::name_ =
    "MissingExportedFunctionTarget";

// An equivalent signature function, but that doubles the input value.
int Double(int i) {
  return 2 * i;
}

TEST(ExportedFunctionTest, Constructor) {
  ExportedFunctionType exported_function;
  EXPECT_TRUE(exported_function.function() == nullptr);
  EXPECT_TRUE(exported_function.callback().is_null());
}

TEST(ExportedFunctionTest, DoesntFindMissingExport) {
  MissingExportedFunctionType exported_function;
  EXPECT_FALSE(exported_function.Lookup());
  EXPECT_TRUE(exported_function.function() == nullptr);
  EXPECT_TRUE(exported_function.callback().is_null());
}

TEST(ExportedFunctionTest, FindsActualExport) {
  ExportedFunctionType exported_function;
  EXPECT_TRUE(exported_function.Lookup());
#ifdef NDEBUG
  EXPECT_EQ(&ExportedFunctionTarget, exported_function.function());
#else
  // In debug builds the function is incrementally linked so there's
  // a level of indirection involved.
  EXPECT_TRUE(exported_function.function() != nullptr);
#endif
  EXPECT_TRUE(exported_function.callback().is_null());
}

TEST(ExportedFunctionTest, InvokesActualExport) {
  ExportedFunctionType exported_function;
  ASSERT_TRUE(exported_function.Lookup());
  ASSERT_TRUE(exported_function.function() != nullptr);
  EXPECT_EQ(37, exported_function.Run(37));
  EXPECT_EQ(42, exported_function.Run(42));
}

TEST(ExportedFunctionTest, InvokesSetFunction) {
  MissingExportedFunctionType exported_function;
  ASSERT_TRUE(exported_function.function() == nullptr);
  ASSERT_TRUE(exported_function.callback().is_null());

  exported_function.set_function(&Double);
  ASSERT_TRUE(exported_function.function() == &Double);
  ASSERT_TRUE(exported_function.callback().is_null());

  EXPECT_EQ(4, exported_function.Run(2));
  EXPECT_EQ(26, exported_function.Run(13));
}

TEST(ExportedFunctionTest, InvokesSetCallback) {
  MissingExportedFunctionType exported_function;
  ASSERT_TRUE(exported_function.function() == nullptr);
  ASSERT_TRUE(exported_function.callback().is_null());

  exported_function.set_callback(base::Bind(&Double));
  ASSERT_TRUE(exported_function.function() == nullptr);
  ASSERT_FALSE(exported_function.callback().is_null());

  EXPECT_EQ(4, exported_function.Run(2));
  EXPECT_EQ(26, exported_function.Run(13));
}

}  // namespace reporters
}  // namespace asan
}  // namespace agent
