// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/kasko/reporter.h"

#include <Windows.h>  // NOLINT
#include <Dbgeng.h>
#include <Rpc.h>

#include <set>
#include <string>

#include "base/bind.h"
#include "base/callback.h"
#include "base/file_util.h"
#include "base/location.h"
#include "base/files/file_enumerator.h"
#include "base/files/file_path.h"
#include "base/files/file_path_watcher.h"
#include "base/files/scoped_temp_dir.h"
#include "base/memory/scoped_ptr.h"
#include "base/message_loop/message_loop.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/time.h"
#include "gtest/gtest.h"
#include "syzygy/common/rpc/helpers.h"
#include "syzygy/kasko/crash_keys_serialization.h"
#include "syzygy/kasko/kasko_rpc.h"
#include "syzygy/kasko/testing/minidump_unittest_helpers.h"
#include "syzygy/kasko/testing/test_server.h"

// The test server will respond to POSTs to /crash by writing all parameters to
// a report directory. Each file in the directory has the name of a parameter
// and the parameter value as its contents.
//
// This test instantiates a reporter process, points it at a test server, and
// then monitors the server's "incoming" director for new files named
// Reporter::kMinidumpUploadFilePart.
namespace kasko {

namespace {

// Invokes the diagnostic report RPC service at |endpoint|, requesting a dump of
// the current process, and including |protobuf|.
void DoInvokeService(const base::string16& endpoint,
                     const std::string& protobuf) {
  common::rpc::ScopedRpcBinding rpc_binding;
  ASSERT_TRUE(rpc_binding.Open(L"ncalrpc", endpoint));

  common::rpc::RpcStatus status = common::rpc::InvokeRpc(
      KaskoClient_SendDiagnosticReport, rpc_binding.Get(), NULL, 0,
      protobuf.length(),
      reinterpret_cast<const signed char*>(protobuf.c_str()));
  ASSERT_FALSE(status.exception_occurred);
  ASSERT_TRUE(status.succeeded());
}

// Verifies that the uploaded minidump is plausibly a dump of this test process.
void ValidateMinidump(IDebugClient4* debug_client,
                      IDebugControl* debug_control,
                      IDebugSymbols* debug_symbols) {
  ASSERT_HRESULT_SUCCEEDED(
      debug_symbols->GetModuleByModuleName("kasko_unittests", 0, NULL, NULL));
}

// Observes changes to the test server's 'incoming' directory. Notifications do
// not specify the individual file changed; for each notification we must scan
// for new minidump files. Once one is found, we verify that it is plausibly a
// crash report from this process and then quit the current message loop.
void WatchForUpload(const base::FilePath& path, bool error) {
  if (error) {
    ADD_FAILURE() << "Failure in path watching.";
    base::MessageLoop::current()->Quit();
    return;
  }

  base::FileEnumerator enumerator(path, true, base::FileEnumerator::FILES);
  for (base::FilePath candidate = enumerator.Next(); !candidate.empty();
       candidate = enumerator.Next()) {
    if (candidate.BaseName() !=
        base::FilePath(Reporter::kMinidumpUploadFilePart)) {
      continue;
    }

    EXPECT_HRESULT_SUCCEEDED(
        testing::VisitMinidump(candidate, base::Bind(&ValidateMinidump)));
    base::MessageLoop::current()->Quit();
  }
}

// Observes changes to the permanent failure destination. Once a complete report
// is found, validates that the report is plausibly a crash report from this
// process and then quits the current message loop.
void WatchForPermanentFailure(const base::FilePath& path, bool error) {
  if (error) {
    ADD_FAILURE() << "Failure in path watching.";
    base::MessageLoop::current()->Quit();
    return;
  }

  base::FileEnumerator enumerator(path, true, base::FileEnumerator::FILES);
  for (base::FilePath candidate = enumerator.Next(); !candidate.empty();
       candidate = enumerator.Next()) {
    LOG(ERROR) << "Candidate: " << candidate.value();
    if (candidate.FinalExtension() !=
        Reporter::kPermanentFailureMinidumpExtension) {
      LOG(ERROR) << "0";
      continue;
    }
    base::FilePath crash_keys_file = candidate.ReplaceExtension(
        Reporter::kPermanentFailureCrashKeysExtension);
    if (!base::PathExists(crash_keys_file)) {
      LOG(ERROR) << "No crash keys at " << crash_keys_file.value();
      continue;
    }
    EXPECT_HRESULT_SUCCEEDED(
        testing::VisitMinidump(candidate, base::Bind(&ValidateMinidump)));
    std::map<base::string16, base::string16> crash_keys;
    EXPECT_TRUE(ReadCrashKeysFromFile(crash_keys_file, &crash_keys));

    base::MessageLoop::current()->Quit();
  }
}

// Starts watching |path| using |watcher|. Must be invoked inside the IO message
// loop. |callback| will be invoked when a change to |path| or its contents is
// detected.
void StartWatch(base::FilePathWatcher* watcher,
                const base::FilePath& path,
                const base::FilePathWatcher::Callback& callback) {
  if (!watcher->Watch(path, true, callback)) {
    ADD_FAILURE() << "Failed to initiate file path watch.";
    base::MessageLoop::current()->Quit();
    return;
  }
}

}  // namespace

TEST(ReporterTest, BasicTest) {
  testing::TestServer server;
  ASSERT_TRUE(server.Start());

  base::ScopedTempDir data_directory;
  base::ScopedTempDir permanent_failure_directory;
  ASSERT_TRUE(data_directory.CreateUniqueTempDir());
  ASSERT_TRUE(permanent_failure_directory.CreateUniqueTempDir());

  scoped_ptr<Reporter> instance(Reporter::Create(
      L"test_endpoint",
      L"http://127.0.0.1:" + base::UintToString16(server.port()) + L"/crash",
      data_directory.path(), permanent_failure_directory.path(),
      base::TimeDelta::FromMilliseconds(1),
      base::TimeDelta::FromMilliseconds(1)));

  ASSERT_TRUE(instance);

  base::FilePathWatcher watcher;
  base::MessageLoop watcher_loop(base::MessageLoop::TYPE_IO);
  watcher_loop.PostTask(
      FROM_HERE,
      base::Bind(&StartWatch, base::Unretained(&watcher),
                 server.incoming_directory(), base::Bind(&WatchForUpload)));
  watcher_loop.PostTask(
      FROM_HERE, base::Bind(&DoInvokeService, base::string16(L"test_endpoint"),
                            std::string("protobuf")));
  watcher_loop.Run();

  Reporter::Shutdown(instance.Pass());
}

TEST(ReporterTest, PermanentFailureTest) {
  testing::TestServer server;
  ASSERT_TRUE(server.Start());

  base::ScopedTempDir data_directory;
  base::ScopedTempDir permanent_failure_directory;
  ASSERT_TRUE(data_directory.CreateUniqueTempDir());
  ASSERT_TRUE(permanent_failure_directory.CreateUniqueTempDir());

  scoped_ptr<Reporter> instance(Reporter::Create(
      L"test_endpoint",
      L"http://127.0.0.1:" + base::UintToString16(server.port()) +
          L"/crash_failure",
      data_directory.path(), permanent_failure_directory.path(),
      base::TimeDelta::FromMilliseconds(1),
      base::TimeDelta::FromMilliseconds(1)));

  ASSERT_TRUE(instance);

  base::FilePathWatcher watcher;
  base::MessageLoop watcher_loop(base::MessageLoop::TYPE_IO);
  watcher_loop.PostTask(FROM_HERE,
                        base::Bind(&StartWatch, base::Unretained(&watcher),
                                   permanent_failure_directory.path(),
                                   base::Bind(&WatchForPermanentFailure)));
  watcher_loop.PostTask(
      FROM_HERE, base::Bind(&DoInvokeService, base::string16(L"test_endpoint"),
                            std::string("protobuf")));
  watcher_loop.Run();

  Reporter::Shutdown(instance.Pass());
}

}  // namespace kasko
