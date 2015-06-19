// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "base/base_switches.h"
#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback_helpers.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/kill.h"
#include "base/process/launch.h"
#include "base/process/process_handle.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/multiprocess_test.h"
#include "base/win/scoped_handle.h"
#include "syzygy/kasko/api/client.h"
#include "syzygy/kasko/api/reporter.h"
#include "syzygy/kasko/testing/minidump_unittest_helpers.h"
#include "syzygy/kasko/testing/test_server.h"
#include "syzygy/kasko/testing/upload_observer.h"
#include "testing/multiprocess_func_list.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace kasko {
namespace api {

namespace {

const char kGlobalString[] = "a global string";

const char kClientProcessIdSwitch[] = "client-process-id";
const char kExpectGlobalSwitch[] = "expect-global";

const base::char16 kExitEventNamePrefix[] = L"kasko_api_test_exit_event_";
const base::char16 kReadyEventNamePrefix[] = L"kasko_api_test_ready_event_";
const base::char16 kEndpointPrefix[] = L"kasko_api_test_endpoint_";

// Verifies the minidump contents and sets the bool pointed to by |context| to
// true.
void OnUploadProc(void* context,
                  const base::char16* report_id,
                  const base::char16* minidump_path,
                  const base::char16* const* keys,
                  const base::char16* const* values) {
  CHECK(report_id);
  CHECK(report_id[0] != 0);
  CHECK(minidump_path);
  CHECK(minidump_path[0] != 0);
  CHECK(keys[0]);
  CHECK(values[0]);
  bool found_hello_world = false;
  for (int i = 0; keys[i] != nullptr; ++i) {
    if (keys[i] == base::string16(L"hello")) {
      CHECK_EQ(base::string16(L"world"), base::string16(values[i]));
      found_hello_world = true;
    }
    // Make sure that the ""="bar" key was dropped along the way.
    CHECK_NE(values[i], base::string16(L"bar"));
    CHECK_NE(keys[i], base::string16());
  }
  CHECK(found_hello_world);
  *reinterpret_cast<bool*>(context) = true;
}

// Implements the setup and teardown of a child process that runs a Kasko
// reporter.
class ChildProcess {
 public:
  ChildProcess()
      : client_process_id_(0), on_upload_invoked_(false) {
    base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
    base::string16 client_process_id_string = base::ASCIIToUTF16(
        cmd_line->GetSwitchValueASCII(kClientProcessIdSwitch));
    unsigned int client_process_id_uint = 0;
    CHECK(
        base::StringToUint(client_process_id_string, &client_process_id_uint));
    client_process_id_ = client_process_id_uint;
    CHECK(permanent_failure_directory_.CreateUniqueTempDir());

    // Set up a directory for the Reporter to generate and store crash dumps.
    CHECK(data_directory_.CreateUniqueTempDir());

    // Start up a test server to receive uploads.
    CHECK(server_.Start());
  }

  // Initializes the reporter, invokes the subclass-implemented OnInitialized,
  // shuts down the reporter (waiting for an upload to complete), then invokes
  // the subclass-implemented OnComplete().
  void Run() {
    base::string16 url =
        L"http://127.0.0.1:" + base::UintToString16(server_.port()) + L"/crash";
    base::string16 endpoint =
        kEndpointPrefix + base::UintToString16(client_process_id_);

    // Initialize the Reporter process
    InitializeReporter(endpoint.c_str(), url.c_str(),
                       data_directory_.path().value().c_str(),
                       permanent_failure_directory_.path().value().c_str(),
                       &OnUploadProc, &on_upload_invoked_);
    observer_.reset(new testing::UploadObserver(
        server_.incoming_directory(), permanent_failure_directory_.path()));
    OnInitialized();

    // Shut down the Reporter process. This will block on upload completion.
    ShutdownReporter();

    base::FilePath minidump_path;
    std::map<std::string, std::string> crash_keys;
    bool success = false;
    observer_->WaitForUpload(&minidump_path, &crash_keys, &success);
    CHECK_EQ(success, on_upload_invoked_);

    OnComplete(success, minidump_path, crash_keys);
  }

 protected:
  base::ProcessId client_process_id() { return client_process_id_; }

 private:
  // Invoked once the reporter is initialized. The reporter will be shut down
  // when this method returns.
  virtual void OnInitialized() = 0;

  // Invoked when the minidump upload has been received by the test server.
  virtual void OnComplete(
      bool success,
      const base::FilePath& minidump_path,
      const std::map<std::string, std::string>& crash_keys) = 0;

  base::ProcessId client_process_id_;
  base::ScopedTempDir permanent_failure_directory_;
  base::ScopedTempDir data_directory_;
  testing::TestServer server_;
  bool on_upload_invoked_;
  scoped_ptr<testing::UploadObserver> observer_;

  DISALLOW_COPY_AND_ASSIGN(ChildProcess);
};

// Uses two events to communicate with the client (parent) process. Expects to
// receive a single invocation of SendDiagnosticReport.
// Verifies that kGlobalString is in the dump if and only if kExpectGlobalSwitch
// is used.
MULTIPROCESS_TEST_MAIN(WaitForClientInvocation) {
  class DoWaitForClientInvocation : public ChildProcess {
   private:
    void OnInitialized() override {
      base::string16 client_process_id_string =
          base::UintToString16(client_process_id());

      // Create the events used for inter-process synchronization.
      base::WaitableEvent exit_event(base::win::ScopedHandle(::CreateEvent(
          NULL, FALSE, FALSE,
          (kExitEventNamePrefix + client_process_id_string).c_str())));
      base::WaitableEvent ready_event(base::win::ScopedHandle(::CreateEvent(
          NULL, FALSE, FALSE,
          (kReadyEventNamePrefix + client_process_id_string).c_str())));

      // Tell the client process that we are active.
      ready_event.Signal();

      // Wait until the client signals us to shut down.
      exit_event.Wait();
    }

    void OnComplete(
        bool success,
        const base::FilePath& minidump_path,
        const std::map<std::string, std::string>& crash_keys) override {
      CHECK(success);
      CHECK(crash_keys.end() != crash_keys.find("hello"));
      CHECK_EQ("world", crash_keys.find("hello")->second);
      // Make sure that the ""="bar" key was dropped along the way.
      for (auto& entry : crash_keys) {
        CHECK_NE("", entry.first);
        CHECK_NE("bar", entry.first);
      }

      base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
      std::string dump;
      CHECK(base::ReadFileToString(minidump_path, &dump));
      if (cmd_line->HasSwitch(kExpectGlobalSwitch)) {
        CHECK_NE(std::string::npos, dump.find(kGlobalString));
      } else {
        CHECK_EQ(std::string::npos, dump.find(kGlobalString));
      }
    }
  };

  DoWaitForClientInvocation().Run();

  return 0;
}

// Invokes SendReportForProcess on the client (parent) process and verifies that
// the dump is correctly taken and uploaded.
MULTIPROCESS_TEST_MAIN(SendReportForProcess) {
  class DoSendReportForProcess : public ChildProcess {
   private:
    void OnInitialized() override {
      // Request a dump of the client process.
      base::char16* keys[] = {L"hello", L"", nullptr};
      base::char16* values[] = {L"world", L"bar", nullptr};
      base::win::ScopedHandle client_process(
          ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, client_process_id()));
      CHECK(client_process.IsValid());

      SendReportForProcess(client_process.Get(), SMALL_DUMP_TYPE, keys, values);
    }

    void OnComplete(
        bool success,
        const base::FilePath& minidump_path,
        const std::map<std::string, std::string>& crash_keys) override {
      CHECK(success);
      CHECK(crash_keys.end() != crash_keys.find("hello"));
      CHECK_EQ("world", crash_keys.find("hello")->second);
      // Make sure that the ""="bar" key was dropped along the way.
      for (auto& entry : crash_keys) {
        CHECK_NE("", entry.first);
        CHECK_NE("bar", entry.first);
      }
    }
  };

  DoSendReportForProcess().Run();

  return 0;
}

// Initializes and shuts down the Kasko client, and provides a helper that
// starts up, invokes, and tears down a reporter process.
class TestClient {
 public:
  TestClient()
      : process_id_string_(base::UintToString16(base::GetCurrentProcId())),
        ready_event_(base::win::ScopedHandle(::CreateEvent(
            nullptr,
            false,
            false,
            (kReadyEventNamePrefix + process_id_string_).c_str()))),
        exit_event_(base::win::ScopedHandle(::CreateEvent(
            nullptr,
            false,
            false,
            (kExitEventNamePrefix + process_id_string_).c_str()))) {
    // Initialize the Client process.
    InitializeClient((kEndpointPrefix + process_id_string_).c_str());
  }

  ~TestClient() { ShutdownClient(); }

  // Starts a reporter process, invokes SendDiagnosticReport, and then tears
  // down the reporter process. If |request_memory_range| is true, inclusion of
  // kGlobalString will be requested (and verified).
  void DoInvokeSendReport(bool request_memory_range) {
    // Start building the Reporter process command line.
    base::CommandLine reporter_command_line =
        base::GetMultiProcessTestChildBaseCommandLine();
    reporter_command_line.AppendSwitchASCII(switches::kTestChildProcess,
                                            "WaitForClientInvocation");

    // Pass the client process ID, used to share event and RPC endpoint names.
    reporter_command_line.AppendSwitchASCII(
        kClientProcessIdSwitch, base::UTF16ToASCII(process_id_string_));

    if (request_memory_range)
      reporter_command_line.AppendSwitch(kExpectGlobalSwitch);

    // Launch the Reporter process and wait until it is fully initialized.
    base::Process reporter_process =
        base::LaunchProcess(reporter_command_line, base::LaunchOptions());
    ASSERT_TRUE(reporter_process.IsValid());
    // Make sure that we terminate the reporter process, even if we ASSERT out
    // of here.
    base::ScopedClosureRunner terminate_reporter_process(
        base::Bind(base::IgnoreResult(&base::Process::Terminate),
                   base::Unretained(&reporter_process), 0, true));

    ready_event_.Wait();

    // Send up a crash report.
    CONTEXT ctx = {};
    ::RtlCaptureContext(&ctx);
    EXCEPTION_RECORD exc_rec = {};
    exc_rec.ExceptionAddress = reinterpret_cast<void*>(ctx.Eip);
    exc_rec.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
    EXCEPTION_POINTERS exc_ptrs = {&exc_rec, &ctx};

    CrashKey crash_keys[] = {{L"hello", L"world"}, {L"", L"bar"}};

    std::vector<MemoryRange> memory_ranges;
    // GetMemoryRange is extracted to prevent kGlobalString from unintentionally
    // being on the stack and potentially being included for that reason.
    if (request_memory_range)
      memory_ranges.push_back(GetMemoryRange());

    SendReport(&exc_ptrs, SMALL_DUMP_TYPE, NULL, 0, crash_keys,
               arraysize(crash_keys), memory_ranges.data(),
               memory_ranges.size());

    // Tell the reporter process it may exit.
    exit_event_.Signal();

    // The reporter process will exit after successfully uploading the generated
    // report and verifying its contents.

    // Wait for the reporter process to exit and verify its status code.
    int exit_code = 0;
    reporter_process.WaitForExit(&exit_code);
    ASSERT_EQ(0, exit_code);
  }

 private:
  MemoryRange GetMemoryRange() {
    MemoryRange memory_range = {reinterpret_cast<const void*>(kGlobalString),
                                sizeof(kGlobalString)};
    return memory_range;
  }

  base::string16 process_id_string_;
  base::WaitableEvent ready_event_;
  base::WaitableEvent exit_event_;

  DISALLOW_COPY_AND_ASSIGN(TestClient);
};

}  // namespace

TEST(ApiTest, ExportedConstants) {
  // Verify that these constants are exported.
  base::string16 crash_keys_extension(
      kasko::api::kPermanentFailureCrashKeysExtension);
  base::string16 minidump_extension(
      kasko::api::kPermanentFailureMinidumpExtension);
}

TEST(ApiTest, SendReportTest) {
  // TODO(erikwright): For now it is impossible to initialize/shutdown the
  // client or reporter twice in the same process. This is because internally,
  // it will spin up and down the AtExitManager, causing singletons to be
  // destroyed (as expected) during shutdown. But base::Singleton does not fully
  // reset its state during the AtExit callback, and as such the second spin-up
  // crashes.
  // Thus, all tests that require InitializeClient to be called must be done in
  // this single test suite, with a single TestClient instance.

  TestClient test_client;
  test_client.DoInvokeSendReport(false);
  test_client.DoInvokeSendReport(true);
}

TEST(ApiTest, SendReportForProcessTest) {
  // Pick an ID used to avoid global namespace collisions.
  base::string16 process_id_string =
      base::UintToString16(base::GetCurrentProcId());

  // Start building the Reporter process command line.
  base::CommandLine reporter_command_line =
      base::GetMultiProcessTestChildBaseCommandLine();
  reporter_command_line.AppendSwitchASCII(switches::kTestChildProcess,
                                          "SendReportForProcess");

  // Pass the client process ID, used to call SendReportForProcess.
  reporter_command_line.AppendSwitchASCII(
      kClientProcessIdSwitch, base::UTF16ToASCII(process_id_string));

  // Launch the Reporter process.
  base::Process reporter_process =
      base::LaunchProcess(reporter_command_line, base::LaunchOptions());
  ASSERT_TRUE(reporter_process.IsValid());

  // The Reporter process will exit after taking a dump of us and verifying its
  // contents.

  // Wait for the reporter process to exit and verify its status code.
  int exit_code = 0;
  reporter_process.WaitForExit(&exit_code);
  ASSERT_EQ(0, exit_code);
}

}  // namespace api
}  // namespace kasko
