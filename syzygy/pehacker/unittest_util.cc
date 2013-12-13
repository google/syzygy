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

#include "syzygy/pehacker/unittest_util.h"

#include "base/json/json_reader.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace testing {

OperationTest::OperationTest() : previous_log_level_(0) {
}

void OperationTest::SetUp() {
  Super::SetUp();

  // Silence logging.
  previous_log_level_ = logging::GetMinLogLevel();
  logging::SetMinLogLevel(logging::LOG_FATAL);
}

void OperationTest::TearDown() {
  // Restore logging to its previous level.
  logging::SetMinLogLevel(previous_log_level_);
  previous_log_level_ = 0;

  Super::TearDown();
}

void OperationTest::InitConfig(const char* config) {
  scoped_ptr<base::Value> value(base::JSONReader::Read(
      config, base::JSON_ALLOW_TRAILING_COMMAS));
  ASSERT_TRUE(value.get() != NULL);
  base::DictionaryValue* dict = NULL;
  ASSERT_TRUE(value->GetAsDictionary(&dict));
  config_.reset(dict);
  value.release();
}

}  // namespace testing
