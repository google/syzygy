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

#ifndef SYZYGY_KASKO_TESTING_UPLOAD_OBSERVER_H_
#define SYZYGY_KASKO_TESTING_UPLOAD_OBSERVER_H_

#include <map>
#include <string>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/simple_thread.h"

namespace kasko {
namespace testing {

// Observes an upload directory and a permanent failure directory to allow tests
// to observe when a crash report has either been successfully uploaded or has
// permanently failed. Requires the observed directories to be empty before
// beginning observation.
class UploadObserver {
 public:
  // Instantiates an instance to watch the supplied directories. The instance
  // must be created before upload attempts begin. The instance is actively
  // observing by the time the constructor returns.
  // @param upload_directory The 'incoming' directory of the TestServer instance
  //     that is listening for crash reports.
  // @param permanent_failure_directory The permanent failure directory
  //     parameter of the reporter under test.
  UploadObserver(const base::FilePath& upload_directory,
                 const base::FilePath& permanent_failure_directory);
  ~UploadObserver();

  // Blocks until a crash report appears in either the upload or permanent
  // failure directory. Returns immediately if the report already appeared since
  // the constructor invocation.
  // @param minidump_path Receives the path to the minidump from the uploaded
  //     crash report.
  // @param crash_keys Receives the crash keys from the uploaded crash
  //     report.
  // @param upload_success Will be set to true if the report appeared in the
  //     upload directory and false if it appeared in the permanent failure
  //     directory.
  void WaitForUpload(base::FilePath* minidump_path,
                     std::map<std::string, std::string>* crash_keys,
                     bool* upload_success);

 private:
  class UploadObserverThread : public base::SimpleThread {
   public:
    UploadObserverThread(const base::FilePath& upload_directory,
                         const base::FilePath& permanent_failure_directory);
    ~UploadObserverThread() override;

    const base::FilePath& minidump_path() { return minidump_path_; }
    const std::map<std::string, std::string>& crash_keys() {
      return crash_keys_;
    }
    bool upload_success() { return upload_success_; }

    void WaitUntilReady();

    // base::SimpleThread implementation.
    void Run() override;

   private:
    void WatchForPermanentFailure(const base::FilePath& path, bool error);
    void WatchForUpload(const base::FilePath& path, bool error);

    base::WaitableEvent ready_;

    base::FilePath upload_directory_;
    base::FilePath permanent_failure_directory_;

    base::FilePath minidump_path_;
    std::map<std::string, std::string> crash_keys_;
    bool upload_success_ = false;

    DISALLOW_COPY_AND_ASSIGN(UploadObserverThread);
  };

  UploadObserverThread thread_;

  DISALLOW_COPY_AND_ASSIGN(UploadObserver);
};

}  // namespace testing
}  // namespace kasko

#endif  // SYZYGY_KASKO_TESTING_UPLOAD_OBSERVER_H_
