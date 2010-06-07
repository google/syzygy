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
// Symbol information service unittests.
#include "sawbuck/log_lib/process_info_service.h"
#include <atlsecurity.h>
#include "gtest/gtest.h"

namespace {

class ProcessInfoServiceTest: public testing::Test {
 public:
  ProcessInfoServiceTest() : kT0(base::Time()), kT1(base::Time::Now()),
      kT2(kT1 + base::TimeDelta::FromMilliseconds(97)) {
  }

 protected:
  void RunningProcess(ULONG process_id, ULONG parent_id, ULONG session_id,
      const SID* user_sid, const char* image_name,
      const wchar_t* command_line) {
    KernelProcessEvents::ProcessInfo info = {
        process_id,
        parent_id,
        session_id,
        {},  // user_sid
        image_name,
        command_line,
      };

    if (user_sid) {
      EXPECT_TRUE(::CopySid(sizeof(info.user_sid),
                            &info.user_sid,
                            const_cast<SID*>(user_sid)));
    }

    service_.OnProcessIsRunning(base::Time::Now(), info);
  }

  void EndProcess(const base::Time& time, ULONG process_id, ULONG parent_id,
      ULONG session_id, const SID* user_sid, const char* image_name,
      const wchar_t* command_line, DWORD exit_code) {
    KernelProcessEvents::ProcessInfo info = {
        process_id,
        parent_id,
        session_id,
        {},  // user_sid
        image_name,
        command_line,
      };

    if (user_sid) {
      EXPECT_TRUE(::CopySid(sizeof(info.user_sid),
                            &info.user_sid,
                            const_cast<SID*>(user_sid)));
    }

    service_.OnProcessEnded(time, info, exit_code);
  }

  void StartProcess(const base::Time& time, ULONG process_id, ULONG parent_id,
      ULONG session_id, const SID* user_sid, const char* image_name,
      const wchar_t* command_line) {
    KernelProcessEvents::ProcessInfo info = {
        process_id,
        parent_id,
        session_id,
        {},  // user_sid
        image_name,
        command_line,
      };

    if (user_sid) {
      EXPECT_TRUE(::CopySid(sizeof(info.user_sid),
                            &info.user_sid,
                            const_cast<SID*>(user_sid)));
    }

    service_.OnProcessStarted(time, info);
  }

  ProcessInfoService service_;
  const base::Time kT0;
  const base::Time kT1;
  const base::Time kT2;
};

const DWORD kPid = 0x42;
const DWORD kParentPid = 0x99;
const DWORD kSession = 1;
const DWORD kExitCode = 33;
const char kImageName[] = "foo.exe";
const wchar_t kCommandLine[] = L"\"c:\\program files\\foo\\foo.exe\" bar";

TEST_F(ProcessInfoServiceTest, LookupOnEmpty) {
  IProcessInfoService::ProcessInfo info = {};

  // Lookups should fail on an empty service.
  EXPECT_FALSE(service_.GetProcessInfo(0, kT0, &info));
  EXPECT_FALSE(service_.GetProcessInfo(kPid, kT0, &info));
}

TEST_F(ProcessInfoServiceTest, IsRunning) {
  RunningProcess(kPid, kParentPid, kSession, Sids::World(),
      kImageName, kCommandLine);

  IProcessInfoService::ProcessInfo info_t0 = {};
  EXPECT_TRUE(service_.GetProcessInfo(kPid, kT0, &info_t0));

  // We can't use EXPECT_EQ on base::Time, because GTest doesn't
  // know how to print them to a stream.
  EXPECT_TRUE(kT0 == info_t0.started_);
  EXPECT_TRUE(kT0 == info_t0.ended_);
  EXPECT_EQ(kPid, info_t0.process_id_);
  EXPECT_EQ(kParentPid, info_t0.parent_process_id_);
  EXPECT_EQ(kSession, info_t0.session_id_);
  EXPECT_STREQ(kCommandLine, info_t0.command_line_.c_str());
  EXPECT_EQ(STILL_ACTIVE, info_t0.exit_code_);

  IProcessInfoService::ProcessInfo info_t1 = {};
  EXPECT_TRUE(service_.GetProcessInfo(kPid, kT1, &info_t1));
  IProcessInfoService::ProcessInfo info_t2 = {};
  EXPECT_TRUE(service_.GetProcessInfo(kPid, kT2, &info_t2));

  EXPECT_TRUE(info_t0 == info_t1);
  EXPECT_TRUE(info_t1 == info_t2);

  IProcessInfoService::ProcessInfo info = {};
  EXPECT_FALSE(service_.GetProcessInfo(kParentPid, kT0, &info));

  // Create an entry for the parent process, and look it up.
  RunningProcess(kParentPid, 0, kSession, Sids::World(),
      kImageName, kCommandLine);
  EXPECT_TRUE(service_.GetProcessInfo(kParentPid, kT0, &info));
  EXPECT_TRUE(service_.GetProcessInfo(kPid, kT0, &info));
}

TEST_F(ProcessInfoServiceTest, IsRunningAndEnds) {
  RunningProcess(kPid, kParentPid, kSession, Sids::World(),
      kImageName, kCommandLine);

  IProcessInfoService::ProcessInfo info = {};
  EXPECT_TRUE(service_.GetProcessInfo(kPid, kT0, &info));
  EXPECT_TRUE(service_.GetProcessInfo(kPid, kT1, &info));
  EXPECT_TRUE(service_.GetProcessInfo(kPid, kT2, &info));

  EndProcess(kT1, kPid, kParentPid, kSession, Sids::World(),
      kImageName, kCommandLine, kExitCode);

  EXPECT_TRUE(service_.GetProcessInfo(kPid, kT0, &info));
  EXPECT_EQ(kExitCode, info.exit_code_);
  EXPECT_TRUE(kT1 == info.ended_);

  EXPECT_FALSE(service_.GetProcessInfo(kPid, kT1, &info));
  EXPECT_FALSE(service_.GetProcessInfo(kPid, kT2, &info));
}

TEST_F(ProcessInfoServiceTest, StartEnd) {
  StartProcess(kT1, kPid, kParentPid, kSession, Sids::World(),
      kImageName, kCommandLine);
  EndProcess(kT2, kPid, kParentPid, kSession, Sids::World(),
      kImageName, kCommandLine, kExitCode);

  IProcessInfoService::ProcessInfo info = {};
  EXPECT_FALSE(service_.GetProcessInfo(kPid, kT0, &info));
  EXPECT_TRUE(service_.GetProcessInfo(kPid, kT1, &info));

  EXPECT_TRUE(kT1 == info.started_);
  EXPECT_TRUE(kT2 == info.ended_);
  EXPECT_EQ(kPid, info.process_id_);
  EXPECT_EQ(kParentPid, info.parent_process_id_);
  EXPECT_EQ(kSession, info.session_id_);
  EXPECT_STREQ(kCommandLine, info.command_line_.c_str());
  EXPECT_EQ(kExitCode, info.exit_code_);

  EXPECT_FALSE(service_.GetProcessInfo(kPid, kT2, &info));
}

TEST_F(ProcessInfoServiceTest, EndStart) {
  // Signal ending ahead of starting, the end result should be equal as
  // the case above, e.g. start, then end.
  EndProcess(kT2, kPid, kParentPid, kSession, Sids::World(),
      kImageName, kCommandLine, kExitCode);
  StartProcess(kT1, kPid, kParentPid, kSession, Sids::World(),
      kImageName, kCommandLine);

  IProcessInfoService::ProcessInfo info = {};
  EXPECT_FALSE(service_.GetProcessInfo(kPid, kT0, &info));
  EXPECT_TRUE(service_.GetProcessInfo(kPid, kT1, &info));

  EXPECT_TRUE(kT1 == info.started_);
  EXPECT_TRUE(kT2 == info.ended_);
  EXPECT_EQ(kPid, info.process_id_);
  EXPECT_EQ(kParentPid, info.parent_process_id_);
  EXPECT_EQ(kSession, info.session_id_);
  EXPECT_STREQ(kCommandLine, info.command_line_.c_str());
  EXPECT_EQ(kExitCode, info.exit_code_);

  EXPECT_FALSE(service_.GetProcessInfo(kPid, kT2, &info));
}

}  // namespace
