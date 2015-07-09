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

#include "syzygy/common/process_utils.h"

#include <algorithm>

#include "gtest/gtest.h"

namespace common {

TEST(ProcessUtilsTest, GetCurrentProcessModules) {
  ModuleVector modules;

  GetCurrentProcessModules(&modules);

  // Make sure our own module is in the list.
  HMODULE exe_module = ::GetModuleHandle(NULL);
  EXPECT_TRUE(
      std::find(modules.begin(), modules.end(), exe_module) != modules.end());

  // We have some imports, so there should be
  // more than just our own module here.
  EXPECT_LT(1U, modules.size());
}

}  // namespace common
