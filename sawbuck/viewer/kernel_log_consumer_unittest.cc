// Copyright 2010 Google Inc.
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
#include "sawbuck/viewer/kernel_log_consumer.h"

#include <vector>
#include <tlhelp32.h>
#include "base/file_path.h"
#include "base/path_service.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "sawbuck/viewer/kernel_log_unittest_data.h"

namespace {

using testing::_;
using testing::ByRef;
using testing::Eq;
using testing::InSequence;
using testing::StrictMock;

class MockKernelModuleEvents: public KernelModuleEvents {
 public:
  MOCK_METHOD3(OnModuleIsLoaded, void(DWORD process_id,
                                      const base::Time& time,
                                      const ModuleInformation& module_info));
  MOCK_METHOD3(OnModuleUnload, void(DWORD process_id,
                                    const base::Time& time,
                                    const ModuleInformation& module_info));
  MOCK_METHOD3(OnModuleLoad, void(DWORD process_id,
                                  const base::Time& time,
                                  const ModuleInformation& module_info));
};

class KernelLogConsumerTest: public testing::Test {
 public:
  KernelLogConsumerTest() {
  }

  virtual void SetUp() {
    consumer_.set_module_event_sink(&events_);
    FilePath src_root;
    ASSERT_TRUE(PathService::Get(base::DIR_SOURCE_ROOT, &src_root));
    test_data_dir_ = src_root.AppendASCII("sawbuck\\viewer\\test_data");

    modules_.assign(testing::module_list,
        testing::module_list + testing::kNumModules);
  }

  void ExpectWaterDownModules() {
    ModuleInfoList::iterator it(modules_.begin());
    for (; it != modules_.end(); ++it) {
      it->image_checksum = 0;
      it->time_date_stamp = 0;
    }
    ExpectModules();
  }

  void ExpectModules() {
    InSequence in;

    for (size_t i = 0; i < modules_.size(); ++i) {
      EXPECT_CALL(events_, OnModuleIsLoaded(_, _, Eq(ByRef(modules_[i]))))
          .Times(1);
    }

    EXPECT_CALL(events_, OnModuleUnload(_, _, modules_[0]))
        .Times(1);
    EXPECT_CALL(events_, OnModuleLoad(_, _, modules_[0]))
        .Times(1);

  }

  void Consume(const wchar_t* file_name) {
    FilePath file_path = test_data_dir_.Append(file_name);

    ASSERT_HRESULT_SUCCEEDED(
        consumer_.OpenFileSession(file_path.value().c_str()));
    ASSERT_HRESULT_SUCCEEDED(consumer_.Consume());
    ASSERT_HRESULT_SUCCEEDED(consumer_.Close());
  }

 protected:
  typedef std::vector<KernelModuleEvents::ModuleInformation> ModuleInfoList;

  StrictMock<MockKernelModuleEvents> events_;
  KernelLogConsumer consumer_;
  FilePath test_data_dir_;
  ModuleInfoList modules_;
};

TEST_F(KernelLogConsumerTest, Log32Version0) {
  consumer_.set_is_64_bit_log(false);
  ExpectWaterDownModules();
  Consume(L"test_data_32_v0.etl");
}

TEST_F(KernelLogConsumerTest, Log32Version1) {
  consumer_.set_is_64_bit_log(false);
  ExpectWaterDownModules();
  Consume(L"test_data_32_v1.etl");
}

TEST_F(KernelLogConsumerTest, Log32Version2) {
  consumer_.set_is_64_bit_log(false);
  ExpectModules();
  Consume(L"test_data_32_v2.etl");
}

TEST_F(KernelLogConsumerTest, Log64Version0) {
  consumer_.set_is_64_bit_log(true);
  ExpectWaterDownModules();
  Consume(L"test_data_64_v0.etl");
}

TEST_F(KernelLogConsumerTest, Log64Version1) {
  consumer_.set_is_64_bit_log(true);
  ExpectWaterDownModules();
  Consume(L"test_data_64_v1.etl");
}

TEST_F(KernelLogConsumerTest, Log64Version2) {
  consumer_.set_is_64_bit_log(true);
  ExpectModules();
  Consume(L"test_data_64_v2.etl");
}

}  // namespace
