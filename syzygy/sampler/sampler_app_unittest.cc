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

#include "syzygy/sampler/sampler_app.h"

#include "base/bind.h"
#include "base/path_service.h"
#include "base/stringprintf.h"
#include "base/files/scoped_temp_dir.h"
#include "base/synchronization/condition_variable.h"
#include "base/threading/thread.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/application.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace sampler {

namespace {

class TestSamplerApp : public SamplerApp {
 public:
  TestSamplerApp()
      : start_profiling_(&cv_lock_),
        start_profiling_counter_(0),
        stop_profiling_(&cv_lock_),
        stop_profiling_counter_(0) {
  }

  using SamplerApp::PidSet;

  using SamplerApp::GetModuleSignature;
  using SamplerApp::set_running;

  using SamplerApp::pids_;
  using SamplerApp::blacklist_pids_;
  using SamplerApp::module_sigs_;
  using SamplerApp::log2_bucket_size_;
  using SamplerApp::sampling_interval_;
  using SamplerApp::running_;

  void WaitUntilStartProfiling() {
    base::AutoLock auto_lock(cv_lock_);
    while (start_profiling_counter_ == 0)
      start_profiling_.Wait();
    --start_profiling_counter_;
  }

  void WaitUntilStopProfiling() {
    base::AutoLock auto_lock(cv_lock_);
    while (stop_profiling_counter_ == 0)
      stop_profiling_.Wait();
    --stop_profiling_counter_;
  }

 protected:
  virtual void OnStartProfiling(
      const SampledModuleCache::Module* module) OVERRIDE {
    DCHECK(module != NULL);
    base::AutoLock auto_lock(cv_lock_);
    ++start_profiling_counter_;
    start_profiling_.Signal();
  }

  virtual void OnStopProfiling(
      const SampledModuleCache::Module* module) OVERRIDE {
    DCHECK(module != NULL);
    base::AutoLock auto_lock(cv_lock_);
    ++stop_profiling_counter_;
    stop_profiling_.Signal();
  }

 private:
  base::Lock cv_lock_;
  base::ConditionVariable start_profiling_;  // Under cv_lock_.
  size_t start_profiling_counter_;  // Under cv_lock_.
  base::ConditionVariable stop_profiling_;  // Under cv_lock_.
  size_t stop_profiling_counter_;  // Under cv_lock_.
};

class SamplerAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;
  typedef common::Application<TestSamplerApp> TestApplication;

  SamplerAppTest()
      : cmd_line_(base::FilePath(L"sampler.exe")),
        impl_(app_.implementation()),
        worker_thread_("worker-thread") {
  }

  virtual void SetUp() OVERRIDE {
    Super::SetUp();

    ASSERT_TRUE(worker_thread_.Start());

    // Setup the IO streams.
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_));
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    ASSERT_NO_FATAL_FAILURE(InitStreams(
        stdin_path_, stdout_path_, stderr_path_));

    // Point the application at the test's command-line and IO streams.
    app_.set_command_line(&cmd_line_);
    app_.set_in(in());
    app_.set_out(out());
    app_.set_err(err());

    test_dll_path = testing::GetOutputRelativePath(testing::kTestDllName);
    ASSERT_TRUE(TestSamplerApp::GetModuleSignature(test_dll_path,
                                                   &test_dll_sig));

    ASSERT_TRUE(PathService::Get(base::FILE_EXE, &self_path));
    ASSERT_TRUE(TestSamplerApp::GetModuleSignature(self_path,
                                                   &self_sig));
  }

  // Runs the application asynchronously. Provides the return value via the
  // output parameter.
  void RunAppAsync(int* ret) {
    DCHECK(ret != NULL);
    *ret = impl_.Run();
  }

  base::FilePath test_dll_path;
  base::FilePath self_path;
  TestSamplerApp::ModuleSignature test_dll_sig;
  TestSamplerApp::ModuleSignature self_sig;

 protected:
  // The command line to be given to the application under test.
  CommandLine cmd_line_;

  // The application object under test.
  TestApplication app_;

  // A reference to the underlying application implementation for convenience.
  TestSamplerApp& impl_;

  // A temporary folder where all IO will be stored.
  base::FilePath temp_dir_;

  // @name File paths used for the standard IO streams.
  // @{
  base::FilePath stdin_path_;
  base::FilePath stdout_path_;
  base::FilePath stderr_path_;
  // @}

  // A worker thread for posting asynchronous tasks.
  base::Thread worker_thread_;
};

}  // namespace

// Comparison operator for ModuleSignatures. This is outside the anonymous
// namespace so that it is found by name resolution.
bool operator==(const TestSamplerApp::ModuleSignature& s1,
                const TestSamplerApp::ModuleSignature& s2) {
  return s1.size == s2.size && s1.time_date_stamp == s2.time_date_stamp &&
      s1.checksum == s2.checksum;
}

TEST_F(SamplerAppTest, ParseEmptyCommandLineFails) {
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SamplerAppTest, ParseEmptyPidsFails) {
  cmd_line_.AppendSwitch(TestSamplerApp::kPids);
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SamplerAppTest, ParseInvalidPidFails) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kPids, "1234,ab");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SamplerAppTest, ParseEmptyPids) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kPids, ",,,");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SamplerAppTest, ParseOnePidWithManyEmptyPids) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kPids, ",1234,,");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  EXPECT_THAT(impl_.pids_, testing::ElementsAre(1234));
  EXPECT_FALSE(impl_.blacklist_pids_);
  EXPECT_THAT(impl_.module_sigs_, testing::ElementsAre(test_dll_sig));
}

TEST_F(SamplerAppTest, ParseNoModulesFails) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kPids, "1234");
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SamplerAppTest, ParseInvalidModuleFails) {
  cmd_line_.AppendArg("this_module_does_not_exist.dll");
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SamplerAppTest, ParseSmallBucketSizeFails) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kBucketSize, "2");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SamplerAppTest, ParseNonPowerOfTwoBucketSizeFails) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kBucketSize, "33");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SamplerAppTest, ParseInvalidBucketSizeFails) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kBucketSize, "yay");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SamplerAppTest, ParseValidBucketSizeMinimal) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kBucketSize, "8");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  EXPECT_TRUE(impl_.pids_.empty());
  EXPECT_TRUE(impl_.blacklist_pids_);
  EXPECT_THAT(impl_.module_sigs_, testing::ElementsAre(test_dll_sig));
  EXPECT_EQ(3u, impl_.log2_bucket_size_);
  EXPECT_EQ(SamplerApp::kDefaultSamplingInterval, impl_.sampling_interval_);
}

TEST_F(SamplerAppTest, ParseTooSmallSamplingIntervalFails) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kSamplingInterval, "1e-7");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SamplerAppTest, ParseInvalidSamplingIntervalFails) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kSamplingInterval, "3zz");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_FALSE(impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(SamplerAppTest, ParseValidSamplingIntervalInteger) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kSamplingInterval, "2");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  EXPECT_TRUE(impl_.pids_.empty());
  EXPECT_TRUE(impl_.blacklist_pids_);
  EXPECT_THAT(impl_.module_sigs_, testing::ElementsAre(test_dll_sig));
  EXPECT_EQ(SamplerApp::kDefaultLog2BucketSize, impl_.log2_bucket_size_);
  EXPECT_EQ(base::TimeDelta::FromSeconds(2), impl_.sampling_interval_);
}

TEST_F(SamplerAppTest, ParseValidSamplingIntervalDecimal) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kSamplingInterval, "1.5");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  EXPECT_TRUE(impl_.pids_.empty());
  EXPECT_TRUE(impl_.blacklist_pids_);
  EXPECT_THAT(impl_.module_sigs_, testing::ElementsAre(test_dll_sig));
  EXPECT_EQ(SamplerApp::kDefaultLog2BucketSize, impl_.log2_bucket_size_);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(1500), impl_.sampling_interval_);
}

TEST_F(SamplerAppTest, ParseValidSamplingIntervalScientific) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kSamplingInterval, "1e-3");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  EXPECT_TRUE(impl_.pids_.empty());
  EXPECT_TRUE(impl_.blacklist_pids_);
  EXPECT_THAT(impl_.module_sigs_, testing::ElementsAre(test_dll_sig));
  EXPECT_EQ(SamplerApp::kDefaultLog2BucketSize, impl_.log2_bucket_size_);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(1), impl_.sampling_interval_);
}

TEST_F(SamplerAppTest, ParseMinimal) {
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  EXPECT_TRUE(impl_.pids_.empty());
  EXPECT_TRUE(impl_.blacklist_pids_);
  EXPECT_THAT(impl_.module_sigs_, testing::ElementsAre(test_dll_sig));
  EXPECT_EQ(SamplerApp::kDefaultLog2BucketSize, impl_.log2_bucket_size_);
  EXPECT_EQ(SamplerApp::kDefaultSamplingInterval, impl_.sampling_interval_);
}

TEST_F(SamplerAppTest, ParseFullWhitelist) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kPids, "1,2,3");
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kBucketSize, "8");
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kSamplingInterval, "1e-3");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  EXPECT_THAT(impl_.pids_, testing::ElementsAre(1, 2, 3));
  EXPECT_FALSE(impl_.blacklist_pids_);
  EXPECT_THAT(impl_.module_sigs_, testing::ElementsAre(test_dll_sig));
  EXPECT_EQ(3, impl_.log2_bucket_size_);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(1), impl_.sampling_interval_);
}

TEST_F(SamplerAppTest, ParseFullBlacklist) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kPids, "1,2,3");
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kBucketSize, "8");
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kSamplingInterval, "1e-3");
  cmd_line_.AppendSwitch(TestSamplerApp::kBlacklistPids);
  cmd_line_.AppendArgPath(test_dll_path);
  cmd_line_.AppendArgPath(self_path);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  EXPECT_THAT(impl_.pids_, testing::ElementsAre(1, 2, 3));
  EXPECT_TRUE(impl_.blacklist_pids_);
  EXPECT_THAT(impl_.module_sigs_,
              testing::ElementsAre(test_dll_sig, self_sig));
  EXPECT_EQ(3, impl_.log2_bucket_size_);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(1), impl_.sampling_interval_);
}

TEST_F(SamplerAppTest, SampleSelfPidWhitelist) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kPids,
      base::StringPrintf("%d", ::GetCurrentProcessId()));
  cmd_line_.AppendArgPath(self_path);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  int ret = 0;
  base::Closure run = base::Bind(
      &SamplerAppTest::RunAppAsync,
      base::Unretained(this),
      base::Unretained(&ret));
  worker_thread_.message_loop()->PostTask(FROM_HERE, run);

  // Wait for profiling to start.
  impl_.WaitUntilStartProfiling();

  // Busy loop for a few seconds. This will guarantee that we get some samples
  // and have non-empty module data.
  base::Time start = base::Time::Now();
  int i = 0;
  while ((base::Time::Now() - start) < base::TimeDelta::FromSeconds(2)) {
    i += rand();
    i ^= rand();
  }

  // Stop the profiler.
  impl_.set_running(false);

  // Stop the worker thread. This will return when the app has returned.
  worker_thread_.Stop();

  // We should also have received a profiling stop event.
  impl_.WaitUntilStopProfiling();

  // TODO(chrisha): Ensure that profiler output was produced.

  ASSERT_EQ(0, ret);
}

}  // namespace sampler
