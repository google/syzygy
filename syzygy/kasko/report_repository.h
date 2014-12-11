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

#ifndef SYZYGY_KASKO_REPORT_REPOSITORY_H_
#define SYZYGY_KASKO_REPORT_REPOSITORY_H_

#include <map>
#include "base/callback.h"
#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/strings/string16.h"
#include "base/time/time.h"

namespace kasko {

// Manages a repository of crash reports that are pending upload. Tracks upload
// attempts and retry intervals and delegates to a permanent failure handler
// after three failed attempts for a given report.
//
// Any number of ReportRepository instances may be used to store reports (via
// StoreReport). Only a single instance should be used for uploading (via
// UploadPendingReport). It's the client's responsibility to enforce this
// requirement.
class ReportRepository {
 public:
  // Attempts to upload the minidump at the specified file path with the given
  // crash keys. Returns true if successful.
  typedef base::Callback<bool(
      const base::FilePath&,
      const std::map<base::string16, base::string16>&)> Uploader;

  // Handles a report that has exceeded the maximum retry attempts. The two file
  // paths point to the minidump file and the crash keys file (formatted as a
  // JSON dictionary). The handler may move the files. If they are left after
  // handling they will be deleted.
  typedef base::Callback<void(const base::FilePath&, const base::FilePath&)>
      PermanentFailureHandler;

  // Provides the current time.
  typedef base::Callback<base::Time(void)> TimeSource;

  // Instantiates a repository.
  // @param repository_path The directory where reports are to be stored.
  // @param retry_interval The minimum time that must elapse between upload
  //     attempts for a given report.
  // @param time_source A source for the current time.
  // @param uploader Used to upload reports.
  // @param permanent_failure_handler Used to handle reports that have exceeded
  //     the maximum retry attempts.
  ReportRepository(const base::FilePath& repository_path,
                   const base::TimeDelta& retry_interval,
                   const TimeSource& time_source,
                   const Uploader& uploader,
                   const PermanentFailureHandler& permanent_failure_handler);

  ~ReportRepository();

  // Stores the provided report in the repository. Does not attempt an upload at
  // this time. The provided file will be moved or deleted by this method.
  // @param minidump_path The path to the minidump file.
  // @param crash_keys The crash keys for the report.
  void StoreReport(
      const base::FilePath& minidump_path,
      const std::map<base::string16, base::string16>& crash_keys);

  // Attempts to upload a pending report, if any. A report is pending if it has
  // never been submitted to an upload attempt or if its most recent upload
  // attempt is older than the configured retry interval.
  // @returns true if there are no pending reports or a report was successfully
  //     uploaded.
  bool UploadPendingReport();

  // @returns true if UploadPendingReport would attempt to upload a report.
  bool HasPendingReports();

 private:
  base::FilePath repository_path_;
  base::TimeDelta retry_interval_;
  TimeSource time_source_;
  Uploader uploader_;
  PermanentFailureHandler permanent_failure_handler_;

  DISALLOW_COPY_AND_ASSIGN(ReportRepository);
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_REPORT_REPOSITORY_H_
