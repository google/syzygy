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

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/files/file_path.h"
#include "base/win/event_trace_controller.h"
#include "base/win/event_trace_provider.h"
#include "sawbuck/log_lib/kernel_log_unittest_data.h"
#include "gtest/gtest.h"

#include <initguid.h>  // NOLINT - must precede only kernel_log_types.h.
#include "sawbuck/log_lib/kernel_log_types.h"

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
    base::win::EtwTraceProperties prop;
    base::win::EtwTraceController::Stop(kTestSessionName, &prop);
  }

  virtual void TearDown() {
    controller_.Stop(NULL);
  }

  void StartFileSession(const wchar_t* file_name) {
    base::FilePath source_root;
    CHECK(PathService::Get(base::DIR_SOURCE_ROOT, &source_root));

    // Create the destination directory if it doesn't exist already.
    base::FilePath dest_dir(source_root.Append(L"sawbuck\\log_lib\\test_data"));
    ASSERT_TRUE(base::CreateDirectory(dest_dir));

    // Construct the file path and delete any
    // previously existing file at that path.
    base::FilePath dest_file(dest_dir.Append(file_name));
    base::DeleteFile(dest_file, false);

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

  void Log32V0ImageEvent(const sym_util::ModuleInformation& module,
                         base::win::EtwEventType event_type) {
    kernel_log_types::ImageLoad32V0 load = {};
    load.BaseAddress = static_cast<ULONG>(module.base_address);
    load.ModuleSize = module.module_size;

    base::win::EtwMofEvent<2> evt(kernel_log_types::kImageLoadEventClass,
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

  void Log32V1ImageEvent(const sym_util::ModuleInformation& module,
                         base::win::EtwEventType event_type) {
    kernel_log_types::ImageLoad32V1 load = {};
    load.BaseAddress = static_cast<ULONG>(module.base_address);
    load.ModuleSize = module.module_size;
    load.ProcessId = ::GetCurrentProcessId();

    base::win::EtwMofEvent<2> evt(kernel_log_types::kImageLoadEventClass,
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

  void Log32V2ImageEvent(const sym_util::ModuleInformation& module,
                         base::win::EtwEventType event_type) {
    kernel_log_types::ImageLoad32V2 load = {};
    load.BaseAddress = static_cast<ULONG>(module.base_address);
    load.ModuleSize = module.module_size;
    load.ProcessId = ::GetCurrentProcessId();
    load.ImageChecksum = module.image_checksum;
    load.TimeDateStamp = module.time_date_stamp;

    base::win::EtwMofEvent<2> evt(kernel_log_types::kImageLoadEventClass,
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

  void Log64V0ImageEvent(const sym_util::ModuleInformation& module,
                         base::win::EtwEventType event_type) {
    kernel_log_types::ImageLoad64V0 load = {};
    load.BaseAddress = static_cast<ULONG>(module.base_address);
    load.ModuleSize = module.module_size;

    base::win::EtwMofEvent<2> evt(kernel_log_types::kImageLoadEventClass,
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

  void Log64V1ImageEvent(const sym_util::ModuleInformation& module,
                         base::win::EtwEventType event_type) {
    kernel_log_types::ImageLoad64V1 load = {};
    load.BaseAddress = static_cast<ULONG>(module.base_address);
    load.ModuleSize = module.module_size;
    load.ProcessId = ::GetCurrentProcessId();

    base::win::EtwMofEvent<2> evt(kernel_log_types::kImageLoadEventClass,
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

  void Log64V2ImageEvent(const sym_util::ModuleInformation& module,
                         base::win::EtwEventType event_type) {
    kernel_log_types::ImageLoad64V2 load = {};
    load.BaseAddress = static_cast<ULONG>(module.base_address);
    load.ModuleSize = module.module_size;
    load.ProcessId = ::GetCurrentProcessId();
    load.ImageChecksum = module.image_checksum;
    load.TimeDateStamp = module.time_date_stamp;

    base::win::EtwMofEvent<2> evt(kernel_log_types::kImageLoadEventClass,
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

  template <class ProcessInfoType, int version>
  void LogProcessEvent(const KernelProcessEvents::ProcessInfo& process,
                       DWORD exit_status,
                       base::win::EtwEventType event_type) {
    ProcessInfoType info = {};

    info.ProcessId = process.process_id;
    info.ParentId = process.parent_id;
    info.SessionId = process.session_id;
    info.ExitStatus = exit_status;
    base::win::EtwMofEvent<4> evt(kernel_log_types::kProcessEventClass,
                                  event_type,
                                  version,
                                  TRACE_LEVEL_INFORMATION);
    evt.SetField(0, FIELD_OFFSET(ProcessInfoType, UserSID), &info);
    size_t sid_len = ::GetLengthSid(const_cast<SID*>(&process.user_sid));
    evt.SetField(1, sid_len, &process.user_sid);
    evt.SetField(2,
                 process.image_name.length() + 1,
                 process.image_name.c_str());

    // For version 2 and better, the command line is also provided.
    if (version > 1) {
      evt.SetField(3,
                   (process.command_line.length() + 1) * sizeof(wchar_t),
                   process.command_line.c_str());
    }

    provider_.Log(evt.get());
  }

  void Log32V1ProcessEvent(const KernelProcessEvents::ProcessInfo& process,
                           DWORD exit_status,
                           base::win::EtwEventType event_type) {
    LogProcessEvent<kernel_log_types::ProcessInfo32V1, 1>(process,
                                                          exit_status,
                                                          event_type);
  }

  void Log32V2ProcessEvent(const KernelProcessEvents::ProcessInfo& process,
                           DWORD exit_status,
                           base::win::EtwEventType event_type) {
    LogProcessEvent<kernel_log_types::ProcessInfo32V2, 2>(process,
                                                          exit_status,
                                                          event_type);
  }

  void Log64V2ProcessEvent(const KernelProcessEvents::ProcessInfo& process,
                           DWORD exit_status,
                           base::win::EtwEventType event_type) {
    LogProcessEvent<kernel_log_types::ProcessInfo64V2, 2>(process,
                                                          exit_status,
                                                          event_type);
  }

  void Log32V3ProcessEvent(const KernelProcessEvents::ProcessInfo& process,
                           DWORD exit_status,
                           base::win::EtwEventType event_type) {
    LogProcessEvent<kernel_log_types::ProcessInfo32V3, 3>(process,
                                                          exit_status,
                                                          event_type);
  }

  void Log64V3ProcessEvent(const KernelProcessEvents::ProcessInfo& process,
                           DWORD exit_status,
                           base::win::EtwEventType event_type) {
    LogProcessEvent<kernel_log_types::ProcessInfo64V3, 3>(process,
                                                          exit_status,
                                                          event_type);
  }

  typedef void (MakeTestData::*LogProcessEventFunc)(
      const KernelProcessEvents::ProcessInfo& process,
      DWORD exit_status, base::win::EtwEventType event_type);

  void LogProcessEvents(LogProcessEventFunc event_func) {
    // Enumerate all but the last process as "is running".
    for (size_t i = 0; i < testing::kNumProcesses - 1; ++i) {
      const KernelProcessEvents::ProcessInfo& process =
          testing::process_list[i];
      (this->*event_func)(process,
                        STILL_ACTIVE,
                        kernel_log_types::kProcessIsRunningEvent);
    }

    // Make as if the last process started, then stopped ~1000 ms later.
    const KernelProcessEvents::ProcessInfo& process =
        testing::process_list[testing::kNumProcesses - 1];
    (this->*event_func)(process,
                        STILL_ACTIVE,
                        kernel_log_types::kProcessStartEvent);
    ::Sleep(1000);
    (this->*event_func)(process,
                        ERROR_SUCCESS,
                        kernel_log_types::kProcessEndEvent);

    // Issue end-of collection notifications for all remaining.
    for (size_t i = 0; i < testing::kNumProcesses - 1; ++i) {
      const KernelProcessEvents::ProcessInfo& process =
          testing::process_list[i];
      (this->*event_func)(process,
                          STILL_ACTIVE,
                          kernel_log_types::kProcessCollectionEnded);
    }
  }

  base::win::EtwTraceProvider provider_;
  base::win::EtwTraceController controller_;
};

TEST_F(MakeTestData, ImageData32Version0) {
  StartFileSession(L"image_data_32_v0.etl");

  // Make as if all modules were loaded at log start.
  for (size_t i = 0; i < testing::kNumModules; ++i) {
    Log32V0ImageEvent(testing::module_list[i],
               kernel_log_types::kImageNotifyIsLoadedEvent);
  }

  // Now make as if the first module is unloaded, then reloaded.
  // We put a sleep in here since the log file retains the wall clock
  // time of the log event, and we want to space those a little for
  // an extra bit of realism.
  ::Sleep(1000);
  Log32V0ImageEvent(testing::module_list[0],
             kernel_log_types::kImageNotifyUnloadEvent);
  ::Sleep(1000);
  Log32V0ImageEvent(testing::module_list[0],
             kernel_log_types::kImageNotifyLoadEvent);
}

TEST_F(MakeTestData, ImageData32Version1) {
  StartFileSession(L"image_data_32_v1.etl");

  // Make as if all modules were loaded at log start.
  for (size_t i = 0; i < testing::kNumModules; ++i) {
    Log32V1ImageEvent(testing::module_list[i],
               kernel_log_types::kImageNotifyIsLoadedEvent);
  }

  // Now make as if the first module is unloaded, then reloaded.
  ::Sleep(1000);
  Log32V1ImageEvent(testing::module_list[0],
             kernel_log_types::kImageNotifyUnloadEvent);
  ::Sleep(1000);
  Log32V1ImageEvent(testing::module_list[0],
             kernel_log_types::kImageNotifyLoadEvent);
}

TEST_F(MakeTestData, ImageData32Version2) {
  StartFileSession(L"image_data_32_v2.etl");

  // Make as if all modules were loaded at log start.
  for (size_t i = 0; i < testing::kNumModules; ++i) {
    Log32V2ImageEvent(testing::module_list[i],
               kernel_log_types::kImageNotifyIsLoadedEvent);
  }

  // Now make as if the first module is unloaded, then reloaded.
  ::Sleep(1000);
  Log32V2ImageEvent(testing::module_list[0],
             kernel_log_types::kImageNotifyUnloadEvent);
  ::Sleep(1000);
  Log32V2ImageEvent(testing::module_list[0],
             kernel_log_types::kImageNotifyLoadEvent);
}

TEST_F(MakeTestData, ImageData64Version0) {
  StartFileSession(L"image_data_64_v0.etl");

  // Make as if all modules were loaded at log start.
  for (size_t i = 0; i < testing::kNumModules; ++i) {
    Log64V0ImageEvent(testing::module_list[i],
               kernel_log_types::kImageNotifyIsLoadedEvent);
  }

  // Now make as if the first module is unloaded, then reloaded.
  ::Sleep(1000);
  Log64V0ImageEvent(testing::module_list[0],
             kernel_log_types::kImageNotifyUnloadEvent);
  ::Sleep(1000);
  Log64V0ImageEvent(testing::module_list[0],
             kernel_log_types::kImageNotifyLoadEvent);
}

TEST_F(MakeTestData, ImageData64Version1) {
  StartFileSession(L"image_data_64_v1.etl");

  // Make as if all modules were loaded at log start.
  for (size_t i = 0; i < testing::kNumModules; ++i) {
    Log64V1ImageEvent(testing::module_list[i],
               kernel_log_types::kImageNotifyIsLoadedEvent);
  }

  // Now make as if the first module is unloaded, then reloaded.
  ::Sleep(1000);
  Log64V1ImageEvent(testing::module_list[0],
             kernel_log_types::kImageNotifyUnloadEvent);
  ::Sleep(1000);
  Log64V1ImageEvent(testing::module_list[0],
             kernel_log_types::kImageNotifyLoadEvent);
}

TEST_F(MakeTestData, ImageData64Version2) {
  StartFileSession(L"image_data_64_v2.etl");

  // Make as if all modules were loaded at log start.
  for (size_t i = 0; i < testing::kNumModules; ++i) {
    Log64V2ImageEvent(testing::module_list[i],
               kernel_log_types::kImageNotifyIsLoadedEvent);
  }

  // Now make as if the first module is unloaded, then reloaded.
  ::Sleep(1000);
  Log64V2ImageEvent(testing::module_list[0],
             kernel_log_types::kImageNotifyUnloadEvent);
  ::Sleep(1000);
  Log64V2ImageEvent(testing::module_list[0],
             kernel_log_types::kImageNotifyLoadEvent);
}

TEST_F(MakeTestData, ProcessInfo32Version1) {
  StartFileSession(L"process_data_32_v1.etl");

  // For the version 1 logs, we don't get any "is running" notifications,
  // so we only log the last process as starting/ending.
  const KernelProcessEvents::ProcessInfo& process =
      testing::process_list[testing::kNumProcesses - 1];
  Log32V1ProcessEvent(process,
                      STILL_ACTIVE,
                      kernel_log_types::kProcessStartEvent);
  ::Sleep(1000);
  Log32V1ProcessEvent(process,
                      ERROR_SUCCESS,
                      kernel_log_types::kProcessEndEvent);
}

TEST_F(MakeTestData, ProcessInfo32Version2) {
  StartFileSession(L"process_data_32_v2.etl");

  LogProcessEvents(&MakeTestData::Log32V2ProcessEvent);
}

TEST_F(MakeTestData, ProcessInfo64Version2) {
  StartFileSession(L"process_data_64_v2.etl");

  LogProcessEvents(&MakeTestData::Log64V2ProcessEvent);
}

TEST_F(MakeTestData, ProcessInfo32Version3) {
  StartFileSession(L"process_data_32_v3.etl");

  LogProcessEvents(&MakeTestData::Log32V3ProcessEvent);
}

TEST_F(MakeTestData, ProcessInfo64Version3) {
  StartFileSession(L"process_data_64_v3.etl");

  LogProcessEvents(&MakeTestData::Log64V3ProcessEvent);
}

}  // namespace

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  CommandLine::Init(argc, argv);
  base::AtExitManager at_exit;
  return RUN_ALL_TESTS();
}
