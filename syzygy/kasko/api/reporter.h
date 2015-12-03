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

#ifndef SYZYGY_KASKO_API_REPORTER_H_
#define SYZYGY_KASKO_API_REPORTER_H_

#include "base/process/process_handle.h"
#include "base/strings/string16.h"
#include "base/threading/platform_thread.h"
#include "syzygy/kasko/api/kasko_export.h"
#include "syzygy/kasko/api/minidump_type.h"

namespace kasko {
namespace api {

// The extension given to crash keys files in the permanent failure directory.
KASKO_EXPORT extern const base::char16* const
    kPermanentFailureCrashKeysExtension;
// The extension given to minidump files in the permanent failure directory.
KASKO_EXPORT extern const base::char16* const
    kPermanentFailureMinidumpExtension;

// Receives notification when a report has been uploaded.
// @param context User-supplied context from InitializeReporter.
// @param report_id The server-assigned report ID.
// @param minidump_path The local path to the report file. This path is no
//     longer valid after the OnUploadProc returns.
// @param keys A null-terminated array of crash key names.
// @param values A null-terminated array of crash key values of equal length to
//     |keys|.
typedef void(OnUploadProc)(void* context,
                           const base::char16* report_id,
                           const base::char16* minidump_path,
                           const base::char16* const* keys,
                           const base::char16* const* values);

// Initializes the Kasko reporter process, including the reporter RPC service
// and background report uploading. Must be matched by a call to
// ShutdownReporter.
//
// Reports that exceed upload retry limits will be moved to the configured
// permanent failure directory. The reports consist of two files: a minidump
// file (extension kPermanentFailureMinidumpExtension, which is '.dmp') and a
// crash keys file (extension kPermanentFailureCrashKeysExtension, which is
// '.kys'). The two file names will be identical apart from the extension. The
// crash keys file will contain a JSON dictionary mapping crash key names to
// string values.
//
// @param endpoint_name The endpoint name that will be used by the Kasko RPC
//     service.
// @param url The URL that will be used for uploading crash reports.
// @param data_directory The directory where crash reports will be queued until
//     uploaded.
// @param permanent_failure_directory The location where reports will be stored
//     once the maximum number of upload attempts has been exceeded.
// @param on_upload_proc An optional procedure to be notified when an upload
//     completes successfully.
// @param on_upload_context A context parameter passed to |on_upload_proc|.
// @returns true if successful.
KASKO_EXPORT bool InitializeReporter(
    const base::char16* endpoint_name,
    const base::char16* url,
    const base::char16* data_directory,
    const base::char16* permanent_failure_directory,
    OnUploadProc* on_upload_proc,
    void* on_upload_context);

// Sends a diagnostic report for a specified process with the specified crash
// keys. May only be invoked after a successful call to InitializeReporter.
// @param process_handle A handle to the process to report on. It must be
//     possible to reopen the process.
// @param thread_id The crashing thread to report on. Ignored if
//     exception_info_address is null.
// @param exception_info_address Optional exception information.
// @param minidump_type The type of minidump to be included in the report.
// @param keys An optional null-terminated array of crash key names
// @param values An optional null-terminated array of crash key values. Must be
//     of equal length to |keys|.
KASKO_EXPORT void SendReportForProcess(
    base::ProcessHandle process_handle,
    base::PlatformThreadId thread_id,
    const EXCEPTION_POINTERS* exception_pointers,
    MinidumpType minidump_type,
    const base::char16* const* keys,
    const base::char16* const* values);

// Shuts down the Kasko reporter process. Must only be called after a successful
// invocation of InitializeReporter.
KASKO_EXPORT void ShutdownReporter();

}  // namespace api
}  // namespace kasko

#endif  // SYZYGY_KASKO_API_REPORTER_H_
