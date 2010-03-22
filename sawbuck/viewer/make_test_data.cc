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
//
// This program generates test data for the kernel_log_consumer unittest,
// which is subsequently checked in to the test_data directory.
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#include "base/event_trace_controller_win.h"
#include "base/event_trace_provider_win.h"
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/pe_image.h"
#include "sawbuck/viewer/kernel_log_unittest_data.h"
#include "gtest/gtest.h"

#include <initguid.h>  // NOLINT - must precede only kernel_log_types.h.
#include "sawbuck/viewer/kernel_log_types.h"

namespace {

// {1103DAD5-FCE6-4ba4-9692-140BB1F16FFB}
DEFINE_GUID(kTestProviderName,
    0x1103dad5, 0xfce6, 0x4ba4,
    0x96, 0x92, 0x14, 0xb, 0xb1, 0xf1, 0x6f, 0xfb);

const wchar_t kTestSessionName[] = L"Make Test Data Session";

class MakeTestData: public testing::Test {
 public:
  MakeTestData() : provider_(kTestProviderName) {
  }

  virtual void SetUp() {
    // Stop any dangling trace session from previous, crashing runs.
    EtwTraceController::Stop(kTestSessionName, NULL);
  }

  virtual void TearDown() {
    controller_.Stop(NULL);
  }

  void StartFileSession(const wchar_t* file_name) {
    FilePath source_root;
    CHECK(PathService::Get(base::DIR_SOURCE_ROOT, &source_root));

    // Create the destination directory if it doesn't exist already.
    FilePath dest_dir(source_root.Append(L"sawbuck\\viewer\\test_data"));
    ASSERT_TRUE(file_util::CreateDirectory(dest_dir));

    // Construct the file path and delete any
    // previously existing file at that path.
    FilePath dest_file(dest_dir.Append(file_name));
    file_util::Delete(dest_file, false);

    // Start a new file session.
    ASSERT_HRESULT_SUCCEEDED(
        controller_.StartFileSession(kTestSessionName,
                                    dest_file.value().c_str(),
                                    false));

    // And enable our test provider.
    ASSERT_HRESULT_SUCCEEDED(
        controller_.EnableProvider(kTestProviderName,
                                  TRACE_LEVEL_VERBOSE,
                                  0xFFFFFFFF));

    // Then register the provider.
    ASSERT_EQ(ERROR_SUCCESS, provider_.Register());
  }

  void Log32V0Event(const sym_util::ModuleInformation& module,
                  EtwEventType event_type) {
    kernel_log_types::ImageLoad32V0 load = {};
    load.BaseAddress = static_cast<ULONG>(module.base_address);
    load.ModuleSize = module.module_size;

    EtwMofEvent<2> evt(kernel_log_types::kImageLoadEventClass,
                       event_type,
                       0,  // version
                       TRACE_LEVEL_INFORMATION);
    evt.SetField(0,
                 FIELD_OFFSET(kernel_log_types::ImageLoad32V0, ImageFileName),
                 &load);
    evt.SetField(1,
                 sizeof(wchar_t) * (module.image_file_name.size() + 1),
                 module.image_file_name.data());
    provider_.Log(evt.get());
  }

  void Log32V1Event(const sym_util::ModuleInformation& module,
                  EtwEventType event_type) {
    kernel_log_types::ImageLoad32V1 load = {};
    load.BaseAddress = static_cast<ULONG>(module.base_address);
    load.ModuleSize = module.module_size;
    load.ProcessId = ::GetCurrentProcessId();

    EtwMofEvent<2> evt(kernel_log_types::kImageLoadEventClass,
                       event_type,
                       1,  // version
                       TRACE_LEVEL_INFORMATION);
    evt.SetField(0,
                 FIELD_OFFSET(kernel_log_types::ImageLoad32V1, ImageFileName),
                 &load);
    evt.SetField(1,
                 sizeof(wchar_t) * (module.image_file_name.size() + 1),
                 module.image_file_name.data());
    provider_.Log(evt.get());
  }

  void Log32V2Event(const sym_util::ModuleInformation& module,
                  EtwEventType event_type) {
    kernel_log_types::ImageLoad32V2 load = {};
    load.BaseAddress = static_cast<ULONG>(module.base_address);
    load.ModuleSize = module.module_size;
    load.ProcessId = ::GetCurrentProcessId();
    load.ImageChecksum = module.image_checksum;
    load.TimeDateStamp = module.time_date_stamp;

    EtwMofEvent<2> evt(kernel_log_types::kImageLoadEventClass,
                       event_type,
                       2,  // version
                       TRACE_LEVEL_INFORMATION);
    evt.SetField(0,
                 FIELD_OFFSET(kernel_log_types::ImageLoad32V2, ImageFileName),
                 &load);
    evt.SetField(1,
                 sizeof(wchar_t) * (module.image_file_name.size() + 1),
                 module.image_file_name.data());
    provider_.Log(evt.get());
  }

  void Log64V0Event(const sym_util::ModuleInformation& module,
                  EtwEventType event_type) {
    kernel_log_types::ImageLoad64V0 load = {};
    load.BaseAddress = static_cast<ULONG>(module.base_address);
    load.ModuleSize = module.module_size;

    EtwMofEvent<2> evt(kernel_log_types::kImageLoadEventClass,
                       event_type,
                       0,  // version
                       TRACE_LEVEL_INFORMATION);
    evt.SetField(0,
                 FIELD_OFFSET(kernel_log_types::ImageLoad64V0, ImageFileName),
                 &load);
    evt.SetField(1,
                 sizeof(wchar_t) * (module.image_file_name.size() + 1),
                 module.image_file_name.data());
    provider_.Log(evt.get());
  }

  void Log64V1Event(const sym_util::ModuleInformation& module,
                  EtwEventType event_type) {
    kernel_log_types::ImageLoad64V1 load = {};
    load.BaseAddress = static_cast<ULONG>(module.base_address);
    load.ModuleSize = module.module_size;
    load.ProcessId = ::GetCurrentProcessId();

    EtwMofEvent<2> evt(kernel_log_types::kImageLoadEventClass,
                       event_type,
                       1,  // version
                       TRACE_LEVEL_INFORMATION);
    evt.SetField(0,
                 FIELD_OFFSET(kernel_log_types::ImageLoad64V1, ImageFileName),
                 &load);
    evt.SetField(1,
                 sizeof(wchar_t) * (module.image_file_name.size() + 1),
                 module.image_file_name.data());
    provider_.Log(evt.get());
  }

  void Log64V2Event(const sym_util::ModuleInformation& module,
                  EtwEventType event_type) {
    kernel_log_types::ImageLoad64V2 load = {};
    load.BaseAddress = static_cast<ULONG>(module.base_address);
    load.ModuleSize = module.module_size;
    load.ProcessId = ::GetCurrentProcessId();
    load.ImageChecksum = module.image_checksum;
    load.TimeDateStamp = module.time_date_stamp;

    EtwMofEvent<2> evt(kernel_log_types::kImageLoadEventClass,
                       event_type,
                       2,  // version
                       TRACE_LEVEL_INFORMATION);
    evt.SetField(0,
                 FIELD_OFFSET(kernel_log_types::ImageLoad64V2, ImageFileName),
                 &load);
    evt.SetField(1,
                 sizeof(wchar_t) * (module.image_file_name.size() + 1),
                 module.image_file_name.data());
    provider_.Log(evt.get());
  }

  EtwTraceProvider provider_;
  EtwTraceController controller_;
};

TEST_F(MakeTestData, Make32Version0Data) {
  StartFileSession(L"test_data_32_v0.etl");

  // Make as if all modules were loaded at log start.
  for (size_t i = 0; i < testing::kNumModules; ++i) {
    Log32V0Event(testing::module_list[i],
               kernel_log_types::kImageNotifyIsLoadedEvent);
  }

  // Now make as if the first module is unloaded, then reloaded.
  // We put a sleep in here since the log file retains the wall clock
  // time of the log event, and we want to space those a little for
  // an extra bit of realism.
  ::Sleep(1000);
  Log32V0Event(testing::module_list[0],
             kernel_log_types::kImageNotifyUnloadEvent);
  ::Sleep(1000);
  Log32V0Event(testing::module_list[0],
             kernel_log_types::kImageNotifyLoadEvent);
}

TEST_F(MakeTestData, Make32Version1Data) {
  StartFileSession(L"test_data_32_v1.etl");

  // Make as if all modules were loaded at log start.
  for (size_t i = 0; i < testing::kNumModules; ++i) {
    Log32V1Event(testing::module_list[i],
               kernel_log_types::kImageNotifyIsLoadedEvent);
  }

  // Now make as if the first module is unloaded, then reloaded.
  ::Sleep(1000);
  Log32V1Event(testing::module_list[0],
             kernel_log_types::kImageNotifyUnloadEvent);
  ::Sleep(1000);
  Log32V1Event(testing::module_list[0],
             kernel_log_types::kImageNotifyLoadEvent);
}

TEST_F(MakeTestData, Make32Version2Data) {
  StartFileSession(L"test_data_32_v2.etl");

  // Make as if all modules were loaded at log start.
  for (size_t i = 0; i < testing::kNumModules; ++i) {
    Log32V2Event(testing::module_list[i],
               kernel_log_types::kImageNotifyIsLoadedEvent);
  }

  // Now make as if the first module is unloaded, then reloaded.
  ::Sleep(1000);
  Log32V2Event(testing::module_list[0],
             kernel_log_types::kImageNotifyUnloadEvent);
  ::Sleep(1000);
  Log32V2Event(testing::module_list[0],
             kernel_log_types::kImageNotifyLoadEvent);
}

TEST_F(MakeTestData, Make64Version0Data) {
  StartFileSession(L"test_data_64_v0.etl");

  // Make as if all modules were loaded at log start.
  for (size_t i = 0; i < testing::kNumModules; ++i) {
    Log64V0Event(testing::module_list[i],
               kernel_log_types::kImageNotifyIsLoadedEvent);
  }

  // Now make as if the first module is unloaded, then reloaded.
  ::Sleep(1000);
  Log64V0Event(testing::module_list[0],
             kernel_log_types::kImageNotifyUnloadEvent);
  ::Sleep(1000);
  Log64V0Event(testing::module_list[0],
             kernel_log_types::kImageNotifyLoadEvent);
}

TEST_F(MakeTestData, Make64Version1Data) {
  StartFileSession(L"test_data_64_v1.etl");

  // Make as if all modules were loaded at log start.
  for (size_t i = 0; i < testing::kNumModules; ++i) {
    Log64V1Event(testing::module_list[i],
               kernel_log_types::kImageNotifyIsLoadedEvent);
  }

  // Now make as if the first module is unloaded, then reloaded.
  ::Sleep(1000);
  Log64V1Event(testing::module_list[0],
             kernel_log_types::kImageNotifyUnloadEvent);
  ::Sleep(1000);
  Log64V1Event(testing::module_list[0],
             kernel_log_types::kImageNotifyLoadEvent);
}

TEST_F(MakeTestData, Make64Version2Data) {
  StartFileSession(L"test_data_64_v2.etl");

  // Make as if all modules were loaded at log start.
  for (size_t i = 0; i < testing::kNumModules; ++i) {
    Log64V2Event(testing::module_list[i],
               kernel_log_types::kImageNotifyIsLoadedEvent);
  }

  // Now make as if the first module is unloaded, then reloaded.
  ::Sleep(1000);
  Log64V2Event(testing::module_list[0],
             kernel_log_types::kImageNotifyUnloadEvent);
  ::Sleep(1000);
  Log64V2Event(testing::module_list[0],
             kernel_log_types::kImageNotifyLoadEvent);
}

}  // namespace

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  CommandLine::Init(argc, argv);
  base::AtExitManager at_exit;
  return RUN_ALL_TESTS();
}
