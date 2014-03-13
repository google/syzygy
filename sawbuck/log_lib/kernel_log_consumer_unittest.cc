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
#include "sawbuck/log_lib/kernel_log_consumer.h"

#include <vector>
#include <tlhelp32.h>
#include "base/path_service.h"
#include "base/files/file_path.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "sawbuck/log_lib/kernel_log_unittest_data.h"

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

class MockKernelProcessEvents: public KernelProcessEvents{
 public:
  MOCK_METHOD2(OnProcessIsRunning, void (const base::Time& time,
                                         const ProcessInfo& process_info));
  MOCK_METHOD2(OnProcessStarted, void (const base::Time& time,
                                       const ProcessInfo& process_info));
  MOCK_METHOD3(OnProcessEnded, void (const base::Time& time,
                                     const ProcessInfo& process_info,
                                     ULONG exit_status));
};

class KernelLogConsumerTest: public testing::Test {
 public:
  KernelLogConsumerTest() {
  }

  virtual void SetUp() {
    base::FilePath src_root;
    ASSERT_TRUE(PathService::Get(base::DIR_SOURCE_ROOT, &src_root));
    image_data_dir_ = src_root.AppendASCII("sawbuck\\log_lib\\test_data");

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
    // We want the module callbacks ordered in the sequence we do the expects.
    InSequence in;

    for (size_t i = 0; i < modules_.size(); ++i) {
      EXPECT_CALL(module_events_,
                  OnModuleIsLoaded(_, _, Eq(ByRef(modules_[i]))))
          .Times(1);
    }

    EXPECT_CALL(module_events_, OnModuleUnload(_, _, modules_[0]))
        .Times(1);
    EXPECT_CALL(module_events_, OnModuleLoad(_, _, modules_[0]))
        .Times(1);

    // Hook up the module event sink.
    consumer_.set_module_event_sink(&module_events_);
  }

  void ExpectProcessStartStop(bool has_command_line) {
    // We want the process callback ordered in the sequence we do the expects.
    InSequence in;

    KernelProcessEvents::ProcessInfo process =
        testing::process_list[testing::kNumProcesses - 1];

    if (!has_command_line)
      process.command_line = L"";

    EXPECT_CALL(process_events_, OnProcessStarted(_, process))
        .Times(1);
    EXPECT_CALL(process_events_, OnProcessEnded(_, process, ERROR_SUCCESS))
        .Times(1);

    // Hook up the module event sink.
    consumer_.set_process_event_sink(&process_events_);
  }

  void ExpectProcesses() {
    // We want the process callbacks in the sequence we do the expects.
    InSequence in;

    for (size_t i = 0; i < testing::kNumProcesses - 1; ++i) {
      const KernelProcessEvents::ProcessInfo& process =
          testing::process_list[i];

      EXPECT_CALL(process_events_, OnProcessIsRunning(_, process))
          .Times(1);
    }

    ExpectProcessStartStop(true);
  }

  void Consume(const wchar_t* file_name) {
    base::FilePath file_path = image_data_dir_.Append(file_name);

    // We don't want to sniff the artificially created
    // test logs for their bitness, as that restricts
    // where we can create those logs.
    consumer_.set_infer_bitness_from_log(false);

    ASSERT_HRESULT_SUCCEEDED(
        consumer_.OpenFileSession(file_path.value().c_str()));
    ASSERT_HRESULT_SUCCEEDED(consumer_.Consume());
    ASSERT_HRESULT_SUCCEEDED(consumer_.Close());
  }

 protected:
  typedef std::vector<KernelModuleEvents::ModuleInformation> ModuleInfoList;

  StrictMock<MockKernelModuleEvents> module_events_;
  StrictMock<MockKernelProcessEvents> process_events_;
  KernelLogConsumer consumer_;
  base::FilePath image_data_dir_;
  ModuleInfoList modules_;
};

TEST_F(KernelLogConsumerTest, ImageEventsLog32Version0) {
  consumer_.set_is_64_bit_log(false);
  ExpectWaterDownModules();
  Consume(L"image_data_32_v0.etl");
}

TEST_F(KernelLogConsumerTest, ImageEventsLog32Version1) {
  consumer_.set_is_64_bit_log(false);
  ExpectWaterDownModules();
  Consume(L"image_data_32_v1.etl");
}

TEST_F(KernelLogConsumerTest, ImageEventsLog32Version2) {
  consumer_.set_is_64_bit_log(false);
  ExpectModules();
  Consume(L"image_data_32_v2.etl");
}

TEST_F(KernelLogConsumerTest, ImageEventsLog64Version0) {
  consumer_.set_is_64_bit_log(true);
  ExpectWaterDownModules();
  Consume(L"image_data_64_v0.etl");
}

TEST_F(KernelLogConsumerTest, ImageEventsLog64Version1) {
  consumer_.set_is_64_bit_log(true);
  ExpectWaterDownModules();
  Consume(L"image_data_64_v1.etl");
}

TEST_F(KernelLogConsumerTest, ImageEventsLog64Version2) {
  consumer_.set_is_64_bit_log(true);
  ExpectModules();
  Consume(L"image_data_64_v2.etl");
}

TEST_F(KernelLogConsumerTest, ProcessEventsLog32Version1) {
  consumer_.set_is_64_bit_log(false);
  // This is the XP case, where we only get process start/stop events.
  ExpectProcessStartStop(false);
  Consume(L"process_data_32_v1.etl");
}

TEST_F(KernelLogConsumerTest, ProcessEventsLog32Version2) {
  consumer_.set_is_64_bit_log(false);
  ExpectProcesses();
  Consume(L"process_data_32_v2.etl");
}

TEST_F(KernelLogConsumerTest, ProcessEventsLog64Version2) {
  consumer_.set_is_64_bit_log(true);
  ExpectProcesses();
  Consume(L"process_data_64_v2.etl");
}

TEST_F(KernelLogConsumerTest, ProcessEventsLog32Version3) {
  consumer_.set_is_64_bit_log(false);
  ExpectProcesses();
  Consume(L"process_data_32_v3.etl");
}

TEST_F(KernelLogConsumerTest, ProcessEventsLog64Version3) {
  consumer_.set_is_64_bit_log(true);
  ExpectProcesses();
  Consume(L"process_data_64_v3.etl");
}

}  // namespace
