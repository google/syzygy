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

#ifndef SYZYGY_KASKO_REPORTER_H_
#define SYZYGY_KASKO_REPORTER_H_

#include <map>
#include <memory>

#include "base/callback_forward.h"
#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/process/process_handle.h"
#include "base/strings/string16.h"
#include "base/threading/platform_thread.h"
#include "syzygy/kasko/report_repository.h"
#include "syzygy/kasko/service_bridge.h"

namespace base {
class TimeDelta;
}  // namespace base

namespace kasko {

struct MinidumpRequest;
class UploadThread;

// Implements the reporter process lifetime. Maintains state, operates a
// reporter RPC service, and configures background uploading of reports.
//
// Reports that exceed upload retry limits will be moved to a permanent failure
// destination. The reports consist of two files: a minidump file (extension
// kPermanentFailureMinidumpExtension, which is '.dmp') and a crash keys file
// (extension kPermanentFailureCrashKeysExtension, which is '.kys'). The two
// file names will be identical apart from the extension. The crash keys file
// will contain a JSON dictionary mapping crash key names to string values.
class Reporter {
 public:
  // The extension given to crash keys files in the permanent failure directory.
  static const base::char16* const kPermanentFailureCrashKeysExtension;
  // The extension given to minidump files in the permanent failure directory.
  static const base::char16* const kPermanentFailureMinidumpExtension;
  // The parameter name assigned to the uploaded minidump file.
  static const base::char16* const kMinidumpUploadFilePart;
  // An crash key added to all reports, indicating the version of Kasko that
  // generated the report.
  static const base::char16* const kKaskoGeneratedByVersion;
  // An crash key added to all reports, indicating the version of Kasko that
  // uploaded the report.
  static const base::char16* const kKaskoUploadedByVersion;

  // Receives notification when a report has been uploaded.
  // @param report_id The server-assigned report ID.
  // @param minidump_path The local path to the report file. This path is no
  //     longer valid after the callback returns.
  // @param crash_keys The crash keys included with the report.
  using OnUploadCallback = base::Callback<void(
      const base::string16& report_id,
      const base::FilePath& minidump_path,
      const std::map<base::string16, base::string16>& crash_keys)>;

  // Creates a Reporter process. The process is already running in the
  // background when this method returns.
  // @param endpoint_name The RPC endpoint name to listen on.
  // @param url The URL that crash reports should be uploaded to.
  // @param data_directory The directory where crash reports will be generated
  //     and stored for uploading.
  // @param permanent_failure_directory The directory where crash reports that
  //     have exceeded retry limits will be moved to.
  // @param upload_interval The minimum interval between two upload operations.
  // @param retry_interval The minimum interval between upload attempts for a
  //     single crash report.
  // @param on_upload_callback The callback to notify when an upload completes.
  // @returns a Reporter instance if successful.
  static std::unique_ptr<Reporter> Create(
      const base::string16& endpoint_name,
      const base::string16& url,
      const base::FilePath& data_directory,
      const base::FilePath& permanent_failure_directory,
      const base::TimeDelta& upload_interval,
      const base::TimeDelta& retry_interval,
      const OnUploadCallback& on_upload_callback);

  ~Reporter();

  // Sends a diagnostic report for a specified process with the specified crash
  // keys.
  // @param process_handle A handle to the process to report on.
  // @param thread_id The crashing thread to report on. Ignored if
  //     request.exception_info_address is null.
  // @param request The report parameters.
  void SendReportForProcess(base::ProcessHandle process_handle,
                            base::PlatformThreadId thread_id,
                            MinidumpRequest request);

  // Shuts down and destroys a Reporter process. Blocks until all background
  // tasks have terminated.
  // @param instance The Reporter process instance to shut down.
  static void Shutdown(std::unique_ptr<Reporter> instance);

  // Uploads a crash report containing the minidump at @p minidump_path and
  // @p crash_keys to @p upload_url. Returns true if successful.
  // @param on_upload_callback The callback to invoke on successful upload.
  // @param upload_url The URL where the minidump will be uploaded.
  // @param minidump_path The path to the minidump to upload.
  // @param crash_keys The crash-keys associated with the minidump.
  // @returns true on success, false otherwise.
  static bool UploadCrashReport(
      const Reporter::OnUploadCallback& on_upload_callback,
      const base::string16& upload_url,
      const base::FilePath& minidump_path,
      const std::map<base::string16, base::string16>& crash_keys);

 private:
  // Instantiates a Reporter process instance. Does not start any background
  // processes.
  // @param report_repository The report repository to store reports in.
  // @param upload_thread An upload thread that is configured to upload reports
  //     from |report_repository|.
  // @param endpoint_name The RPC endpoint name to listen on.
  // @param temporary_minidump_directory A directory where minidumps may be
  //     temporarily stored before uploading.
  Reporter(std::unique_ptr<ReportRepository> report_repository,
           std::unique_ptr<UploadThread> upload_thread,
           const base::string16& endpoint_name,
           const base::FilePath& temporary_minidump_directory);

  // A repository for generated reports.
  std::unique_ptr<ReportRepository> report_repository_;

  // A background upload scheduler.
  std::unique_ptr<UploadThread> upload_thread_;

  // The directory where minidumps will be initially created.
  base::FilePath temporary_minidump_directory_;

  // An RPC service endpoint.
  ServiceBridge service_bridge_;

  DISALLOW_COPY_AND_ASSIGN(Reporter);
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_REPORTER_H_
