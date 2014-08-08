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
#include "base/files/file_enumerator.h"
#include "base/files/scoped_temp_dir.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/condition_variable.h"
#include "base/threading/thread.h"
#include "base/win/pe_image.h"
#include "base/win/windows_version.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/application.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/parse/parser.h"
#include "syzygy/trace/parse/unittest_util.h"

namespace sampler {

namespace {

using testing::_;

const base::TimeDelta kDefaultSamplingInterval;

class TestSamplerApp : public SamplerApp {
 public:
  TestSamplerApp()
      : start_profiling_(&cv_lock_),
        start_profiling_counter_(0),
        stop_profiling_(&cv_lock_),
        stop_profiling_counter_(0),
        on_stop_profiling_sample_count_(0) {
  }

  using SamplerApp::PidSet;

  using SamplerApp::GetModuleSignature;
  using SamplerApp::set_running;

  using SamplerApp::pids_;
  using SamplerApp::blacklist_pids_;
  using SamplerApp::output_dir_;
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

  // Waits until a module has finished profiling, returning the total number of
  // samples set.
  uint64 WaitUntilStopProfiling() {
    base::AutoLock auto_lock(cv_lock_);
    while (stop_profiling_counter_ == 0)
      stop_profiling_.Wait();
    --stop_profiling_counter_;
    return on_stop_profiling_sample_count_;
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

    // Count up the number of samples.
    on_stop_profiling_sample_count_ = 0;
    for (size_t i = 0; i < module->profiler().buckets().size(); ++i)
      on_stop_profiling_sample_count_ += module->profiler().buckets()[i];

    ++stop_profiling_counter_;
    stop_profiling_.Signal();
  }

 private:
  base::Lock cv_lock_;
  base::ConditionVariable start_profiling_;  // Under cv_lock_.
  size_t start_profiling_counter_;  // Under cv_lock_.
  base::ConditionVariable stop_profiling_;  // Under cv_lock_.
  size_t stop_profiling_counter_;  // Under cv_lock_.

  // This will be set to the total number of samples collected in the last
  // OnStopProfiling event.
  uint64 on_stop_profiling_sample_count_;  // Under cv_lock_.
};

class TestParseEventHandler : public testing::MockParseEventHandler {
 public:
  TestParseEventHandler() : sample_count(0) {
    ::memset(&trace_sample_data, 0, sizeof(trace_sample_data));
  }

  // This is used to inspect the results of an OnSampleData call. We remember
  // the number of samples in trace_sample_data_sample_count_.
  void TestOnSampleData(base::Time time,
                        DWORD process_id,
                        const TraceSampleData* data) {
    DCHECK(data != NULL);
    sample_count = 0;
    for (size_t i = 0; i < data->bucket_count; ++i)
      sample_count += data->buckets[i];

    ::memcpy(&trace_sample_data, data, sizeof(trace_sample_data));
  }

  // This will be a copy of the TraceSampleData buffer seen by the last
  // call to TestOnSampleData, minus the bucket table.
  TraceSampleData trace_sample_data;

  // This will be set to the total number of samples seen in the last
  // TraceSampleData buffer seen by TestOnSampleData.
  uint64 sample_count;
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

    output_dir = temp_dir_.AppendASCII("output");
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

  // The trace file directory.
  base::FilePath output_dir;

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
  EXPECT_EQ(kDefaultSamplingInterval, impl_.sampling_interval_);
  EXPECT_TRUE(impl_.output_dir_.empty());
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
  EXPECT_TRUE(impl_.output_dir_.empty());
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
  EXPECT_TRUE(impl_.output_dir_.empty());
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
  EXPECT_TRUE(impl_.output_dir_.empty());
}

TEST_F(SamplerAppTest, ParseOutputDir) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kOutputDir, "foo");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  EXPECT_TRUE(impl_.pids_.empty());
  EXPECT_TRUE(impl_.blacklist_pids_);
  EXPECT_THAT(impl_.module_sigs_, testing::ElementsAre(test_dll_sig));
  EXPECT_EQ(SamplerApp::kDefaultLog2BucketSize, impl_.log2_bucket_size_);
  EXPECT_EQ(kDefaultSamplingInterval, impl_.sampling_interval_);
  EXPECT_EQ(base::FilePath(L"foo"), impl_.output_dir_);
}

TEST_F(SamplerAppTest, ParseMinimal) {
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  EXPECT_TRUE(impl_.pids_.empty());
  EXPECT_TRUE(impl_.blacklist_pids_);
  EXPECT_THAT(impl_.module_sigs_, testing::ElementsAre(test_dll_sig));
  EXPECT_EQ(SamplerApp::kDefaultLog2BucketSize, impl_.log2_bucket_size_);
  EXPECT_EQ(kDefaultSamplingInterval, impl_.sampling_interval_);
  EXPECT_TRUE(impl_.output_dir_.empty());
}

TEST_F(SamplerAppTest, ParseFullWhitelist) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kPids, "1,2,3");
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kBucketSize, "8");
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kSamplingInterval, "1e-3");
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kOutputDir, "foo");
  cmd_line_.AppendArgPath(test_dll_path);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  EXPECT_THAT(impl_.pids_, testing::ElementsAre(1, 2, 3));
  EXPECT_FALSE(impl_.blacklist_pids_);
  EXPECT_THAT(impl_.module_sigs_, testing::ElementsAre(test_dll_sig));
  EXPECT_EQ(3, impl_.log2_bucket_size_);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(1), impl_.sampling_interval_);
  EXPECT_EQ(base::FilePath(L"foo"), impl_.output_dir_);
}

TEST_F(SamplerAppTest, ParseFullBlacklist) {
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kPids, "1,2,3");
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kBucketSize, "8");
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kSamplingInterval, "1e-3");
  cmd_line_.AppendSwitch(TestSamplerApp::kBlacklistPids);
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kOutputDir, "foo");
  cmd_line_.AppendArgPath(test_dll_path);
  cmd_line_.AppendArgPath(self_path);
  ASSERT_TRUE(impl_.ParseCommandLine(&cmd_line_));

  EXPECT_THAT(impl_.pids_, testing::ElementsAre(1, 2, 3));
  EXPECT_TRUE(impl_.blacklist_pids_);
  EXPECT_THAT(impl_.module_sigs_,
              testing::ElementsAre(test_dll_sig, self_sig));
  EXPECT_EQ(3, impl_.log2_bucket_size_);
  EXPECT_EQ(base::TimeDelta::FromMilliseconds(1), impl_.sampling_interval_);
  EXPECT_EQ(base::FilePath(L"foo"), impl_.output_dir_);
}

TEST_F(SamplerAppTest, SampleSelfPidWhitelist) {
  // TODO(chrisha): This test currently times out on Windows 8. Fix it :-)
  // See https://code.google.com/p/sawbuck/issues/detail?id=86 for details.
  if (base::win::GetVersion() >= base::win::VERSION_WIN8)
    return;

  cmd_line_.AppendSwitchASCII(TestSamplerApp::kPids,
      base::StringPrintf("%d", ::GetCurrentProcessId()));
  cmd_line_.AppendSwitchASCII(TestSamplerApp::kSamplingInterval, "0.25");
  cmd_line_.AppendSwitchPath(TestSamplerApp::kOutputDir, output_dir);
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

  // We expect the output directory to exist by now.
  EXPECT_TRUE(base::PathExists(output_dir));

  // Stop the profiler.
  impl_.set_running(false);

  // Stop the worker thread. This will return when the app has returned.
  worker_thread_.Stop();

  // We should also have received a profiling stop event.
  uint32 sample_count = impl_.WaitUntilStopProfiling();

  // NOTE: There's no way for us to find out exactly when the sampler has
  //     started, and under high load the system may defer starting the sampler
  //     or not process the interrupts. Thus, any test that inspects the
  //     number of samplers seen by the profiler is doomed to be flaky.

  // Ensure that profiler output was produced.
  base::FileEnumerator fe(output_dir,
                          false,
                          base::FileEnumerator::FILES,
                          L"*.*");
  base::FilePath dmp_path = fe.Next();
  EXPECT_FALSE(dmp_path.empty());

  int64 dmp_size = 0;
  EXPECT_TRUE(base::GetFileSize(dmp_path, &dmp_size));
  EXPECT_LT(0, dmp_size);

  // We expect no other output to have been produced.
  EXPECT_TRUE(fe.Next().empty());

  ASSERT_EQ(0, ret);

  // Now parse the generated trace file. We expect it to parse without issues
  // and to contain a process started, process attached to module, and module
  // sample data events.
  testing::StrictMock<TestParseEventHandler> parse_handler;
  {
    testing::InSequence in_sequence;
    EXPECT_CALL(parse_handler, OnProcessStarted(_, _, _)).Times(1);
    EXPECT_CALL(parse_handler, OnProcessAttach(_, _, _, _)).Times(1);
    EXPECT_CALL(parse_handler, OnSampleData(_, _, _)).Times(1).WillOnce(
        testing::Invoke(&parse_handler,
                        &TestParseEventHandler::TestOnSampleData));
  }

  trace::parser::Parser parser;
  ASSERT_TRUE(parser.Init(&parse_handler));
  ASSERT_TRUE(parser.OpenTraceFile(dmp_path));
  ASSERT_TRUE(parser.Consume());
  ASSERT_FALSE(parser.error_occurred());
  ASSERT_TRUE(parser.Close());

  // Make sure that the TraceModuleData the parser saw agrees with our
  // expectations.
  base::win::PEImage pe_image(::GetModuleHandleA(NULL));
  EXPECT_EQ(reinterpret_cast<ModuleAddr>(pe_image.module()),
            parse_handler.trace_sample_data.module_base_addr);
  EXPECT_EQ(pe_image.GetNTHeaders()->OptionalHeader.SizeOfImage,
            parse_handler.trace_sample_data.module_size);
  EXPECT_EQ(pe_image.GetNTHeaders()->OptionalHeader.CheckSum,
            parse_handler.trace_sample_data.module_checksum);
  EXPECT_EQ(pe_image.GetNTHeaders()->FileHeader.TimeDateStamp,
            parse_handler.trace_sample_data.module_time_date_stamp);
  EXPECT_EQ(sample_count, parse_handler.sample_count);
}

}  // namespace sampler
