// Copyright 2011 Google Inc.
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
// Main function for common unittests.
#include <atlbase.h>
#include <atlcom.h>
#include "base/at_exit.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

// We're testing ATL code that requires a module object.
class ObligatoryModule: public CAtlModuleT<ObligatoryModule> {
};

ObligatoryModule g_obligatory_atl_module;

int main(int argc, char **argv) {
  base::AtExitManager exit_manager;
  testing::InitGoogleMock(&argc, argv);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
