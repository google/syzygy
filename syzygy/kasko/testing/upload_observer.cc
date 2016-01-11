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

#include "syzygy/kasko/testing/upload_observer.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/files/file_enumerator.h"
#include "base/files/file_path_watcher.h"
#include "base/files/file_util.h"
#include "base/message_loop/message_loop.h"
#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"
#include "syzygy/kasko/crash_keys_serialization.h"
#include "syzygy/kasko/reporter.h"

namespace kasko {
namespace testing {

namespace {
// Starts watching |path| using |watcher|. Must be invoked inside the IO message
// loop. |callback| will be invoked when a change to |path| or its contents is
// detected.
void StartWatch(base::FilePathWatcher* watcher,
                const base::FilePath& path,
                const base::FilePathWatcher::Callback& callback) {
  LOG(INFO) << "Watching " << path.value();
  if (!watcher->Watch(path, true, callback)) {
    ADD_FAILURE() << "Failed to initiate file path watch.";
    base::MessageLoop::current()->QuitNow();
    return;
  }
}
}  // namespace

UploadObserver::UploadObserver(
    const base::FilePath& upload_directory,
    const base::FilePath& permanent_failure_directory)
    : thread_(upload_directory, permanent_failure_directory) {
  thread_.Start();
  // Wait until the file watchers have been initialized.
  thread_.WaitUntilReady();
}

UploadObserver::~UploadObserver() {
  CHECK(thread_.HasBeenJoined());
}

void UploadObserver::WaitForUpload(base::FilePath* minidump_path,
                     std::map<std::string, std::string>* crash_keys,
                     bool* upload_success) {
  LOG(INFO) << "Waiting for an upload.";

  DCHECK(minidump_path);
  DCHECK(crash_keys);
  DCHECK(upload_success);

  // The thread exits once it detects and extracts the data from a crash report.
  thread_.Join();

  // Copy out the data that was extracted by the thread.
  *minidump_path = thread_.minidump_path();
  *crash_keys = thread_.crash_keys();
  *upload_success = thread_.upload_success();

  LOG(INFO) << "Wait for upload completed. Upload path: "
            << thread_.minidump_path().value();
}

UploadObserver::UploadObserverThread::UploadObserverThread(
    const base::FilePath& upload_directory,
    const base::FilePath& permanent_failure_directory)
    : base::SimpleThread("UploadObserver thread"),
      ready_(false, false),
      upload_directory_(upload_directory),
      permanent_failure_directory_(permanent_failure_directory) {
}

UploadObserver::UploadObserverThread::~UploadObserverThread(){
}

void UploadObserver::UploadObserverThread::WaitUntilReady() {
  LOG(INFO) << "Waiting for watch to initiate.";
  ready_.Wait();
  LOG(INFO) << "Watch initiated.";
}

void UploadObserver::UploadObserverThread::Run() {
  base::FilePathWatcher success_watcher;
  base::FilePathWatcher failure_watcher;
  base::MessageLoop watcher_loop(base::MessageLoop::TYPE_IO);

  // Queue up tasks to initialize the watchers on |watcher_loop|.
  watcher_loop.PostTask(
      FROM_HERE,
      base::Bind(&StartWatch, base::Unretained(&success_watcher),
                 upload_directory_,
                 base::Bind(&UploadObserverThread::WatchForUpload,
                            base::Unretained(this))));
  watcher_loop.PostTask(
      FROM_HERE,
      base::Bind(&StartWatch, base::Unretained(&failure_watcher),
                 permanent_failure_directory_,
                 base::Bind(&UploadObserverThread::WatchForPermanentFailure,
                            base::Unretained(this))));

  // Queue up a task to notify the main thread after the watchers are
  // initialized.
  watcher_loop.PostTask(FROM_HERE, base::Bind(&base::WaitableEvent::Signal,
                                              base::Unretained(&ready_)));

  LOG(INFO) << "Running background thread.";

  // Run the loop. This will block until one of the watcher callbacks detects
  // and extracts the data from a crash report.
  watcher_loop.Run();

  LOG(INFO) << "Background thread terminating.";
}

// Observes changes to the test server's 'incoming' directory. Notifications do
// not specify the individual file changed; for each notification we must scan
// for new minidump files. Once one is found, we store the minidump path and
// crash keys and then quit the current message loop.
void UploadObserver::UploadObserverThread::WatchForUpload(
    const base::FilePath& path,
    bool error) {
  LOG(INFO) << "Detected potential upload in " << path.value();

  if (error) {
    ADD_FAILURE() << "Failure in path watching.";
    base::MessageLoop::current()->QuitNow();
    return;
  }

  bool found_minidump = false;
  std::vector<base::FilePath> crash_key_files;
  base::FileEnumerator enumerator(path, true, base::FileEnumerator::FILES);
  for (base::FilePath candidate = enumerator.Next(); !candidate.empty();
       candidate = enumerator.Next()) {
    LOG(INFO) << "Inspecting candidate: " << candidate.value();
    if (candidate.BaseName() !=
        base::FilePath(Reporter::kMinidumpUploadFilePart)) {
      crash_key_files.push_back(candidate);
    } else {
      minidump_path_ = candidate;
      found_minidump = true;
    }
  }

  if (found_minidump) {
    // We depend on the fact that the minidump and crash keys appear atomically.
    for (const auto& crash_key_file : crash_key_files) {
      std::string crash_key_value;
      bool read_crash_key_result =
          base::ReadFileToString(crash_key_file, &crash_key_value);
      EXPECT_TRUE(read_crash_key_result);
      crash_keys_[base::UTF16ToUTF8(crash_key_file.BaseName().value())] =
          crash_key_value;
    }
    upload_success_ = true;
    base::MessageLoop::current()->QuitWhenIdle();
  } else {
    LOG(INFO) << "No minidump file detected.";
  }
}

// Observes changes to the permanent failure destination. Once a complete report
// is found, we store the minidump path and crash keys and then quit the current
// message loop.
void UploadObserver::UploadObserverThread::WatchForPermanentFailure(
    const base::FilePath& path,
    bool error) {
  LOG(INFO) << "Detected potential permanent failure in " << path.value();
  if (error) {
    ADD_FAILURE() << "Failure in path watching.";
    base::MessageLoop::current()->QuitNow();
    return;
  }

  // We are notified when the directory changes. It's possible only one of the
  // minidump file or crash keys file is present, in which case we will wait for
  // a subsequent notification for the other file.
  base::FileEnumerator enumerator(path, true, base::FileEnumerator::FILES);
  for (base::FilePath candidate = enumerator.Next(); !candidate.empty();
       candidate = enumerator.Next()) {
    LOG(INFO) << "Inspecting candidate: " << candidate.value();

    // We are scanning for a minidump file.
    if (candidate.FinalExtension() !=
        Reporter::kPermanentFailureMinidumpExtension) {
      LOG(INFO) << "Extension " << candidate.FinalExtension()
                << " doesn't match "
                << Reporter::kPermanentFailureMinidumpExtension;
      continue;
    }

    // If we found a minidump file, see if we also find a matching crash keys
    // file.
    base::FilePath crash_keys_file = candidate.ReplaceExtension(
        Reporter::kPermanentFailureCrashKeysExtension);
    if (!base::PathExists(crash_keys_file)) {
      LOG(INFO) << "Expected crash keys file " << crash_keys_file.value()
                << " is missing.";
      continue;
    }

    // Copy the data out of the crash keys file.
    std::map<base::string16, base::string16> crash_keys;
    EXPECT_TRUE(ReadCrashKeysFromFile(crash_keys_file, &crash_keys));
    minidump_path_ = candidate;
    for (const auto& entry : crash_keys) {
      crash_keys_[base::UTF16ToUTF8(entry.first)] =
          base::UTF16ToUTF8(entry.second);
    }
    upload_success_ = false;
    base::MessageLoop::current()->QuitWhenIdle();
    LOG(INFO) << "Successfully detected a minidump file.";
    return;
  }

  LOG(INFO) << "No minidump file detected.";
}

}  // namespace testing
}  // namespace kasko
