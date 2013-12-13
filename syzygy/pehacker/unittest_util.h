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

#ifndef SYZYGY_PEHACKER_UNITTEST_UTIL_H_
#define SYZYGY_PEHACKER_UNITTEST_UTIL_H_

#include "base/values.h"
#include "gtest/gtest.h"
#include "syzygy/pe/unittest_util.h"

namespace testing {

class OperationTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  OperationTest();

  void SetUp();

  void TearDown();

  void InitConfig(const char* config);

  // Returns the configuration dictionary.
  const DictionaryValue* config() const { return config_.get(); }

 protected:
  int previous_log_level_;
  scoped_ptr<base::DictionaryValue> config_;
};

}  // namespace testing

#endif  // SYZYGY_PEHACKER_UNITTEST_UTIL_H_
