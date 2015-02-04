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

#include <stdint.h>

#include <map>
#include <string>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "syzygy/kasko/http_agent_impl.h"
#include "syzygy/kasko/minidump.h"
#include "syzygy/kasko/service.h"
#include "syzygy/kasko/upload.h"
#include "syzygy/kasko/upload_thread.h"
#include "syzygy/kasko/version.h"
#include "syzygy/kasko/waitable_timer.h"
#include "syzygy/kasko/waitable_timer_impl.h"

namespace kasko {

namespace {

// The RPC protocol used for receiving dump requests.
const base::char16* const kRpcProtocol = L"ncalrpc";

// The subdirectory where minidumps are generated.
const base::char16* const kTemporarySubdir = L"Temporary";

// Uploads a crash report containing the minidump at |minidump_path| and
// |crash_keys| to |upload_url|. Returns true if successful.
bool UploadCrashReport(
    const base::string16& upload_url,
    const base::FilePath& minidump_path,
    const std::map<base::string16, base::string16>& crash_keys) {
  std::string dump_contents;
  if (!base::ReadFileToString(minidump_path, &dump_contents)) {
    LOG(ERROR) << "Failed to read the minidump file at "
               << minidump_path.value();
    return false;
  }

  HttpAgentImpl http_agent(
      L"Kasko", base::ASCIIToUTF16(KASKO_VERSION_STRING));
  base::string16 remote_dump_id;
  uint16_t response_code = 0;
  if (!SendHttpUpload(&http_agent, upload_url, crash_keys, dump_contents,
                      Reporter::kMinidumpUploadFilePart, &remote_dump_id,
                      &response_code)) {
    LOG(ERROR) << "Failed to upload the minidump file to " << upload_url;
    return false;
  } else {
    // TODO(erikwright): Log this report ID somewhere accessible to our client.
    // For example, the Windows Event Log.
    LOG(INFO) << "Successfully uploded a crash report. Report ID: "
              << remote_dump_id;
  }

  return true;
}

// Moves |minidump_path| and |crash_keys_path| to |permanent_failure_directory|.
// The destination filenames have the filename from |minidump_path| and the
// extensions Reporter::kPermanentFailureMinidumpExtension and
// Reporter::kPermanentFailureCrashKeysExtension.
void HandlePermanentFailure(const base::FilePath& permanent_failure_directory,
                            const base::FilePath& minidump_path,
                            const base::FilePath& crash_keys_path) {
  base::FilePath minidump_target = permanent_failure_directory.Append(
      minidump_path.BaseName().ReplaceExtension(
          Reporter::kPermanentFailureMinidumpExtension));

  // Note that we take the filename from the minidump file, in order to
  // guarantee that the two files have matching names.
  base::FilePath crash_keys_target = permanent_failure_directory.Append(
      minidump_path.BaseName().ReplaceExtension(
          Reporter::kPermanentFailureCrashKeysExtension));

  if (!base::CreateDirectory(permanent_failure_directory)) {
    LOG(ERROR) << "Failed to create directory at "
               << permanent_failure_directory.value();
  } else if (!base::Move(minidump_path, minidump_target)) {
    LOG(ERROR) << "Failed to move " << minidump_path.value() << " to "
               << minidump_target.value();
  } else if (!base::Move(crash_keys_path, crash_keys_target)) {
    LOG(ERROR) << "Failed to move " << crash_keys_path.value() << " to "
               << crash_keys_target.value();
  }
}

void SendReportImpl(const base::FilePath& temporary_directory,
                    ReportRepository* report_repository,
                    base::ProcessId client_process_id,
                    uint64_t exception_info_address,
                    base::PlatformThreadId thread_id,
                    const char* protobuf,
                    size_t protobuf_length,
                    std::map<base::string16, base::string16> crash_keys) {
  if (!base::CreateDirectory(temporary_directory)) {
    LOG(ERROR) << "Failed to create dump destination directory: "
               << temporary_directory.value();
    return;
  }

  base::FilePath dump_file;
  if (!base::CreateTemporaryFileInDir(temporary_directory, &dump_file)) {
    LOG(ERROR) << "Failed to create a temporary dump file.";
    return;
  }

  if (!GenerateMinidump(dump_file, client_process_id, thread_id,
                        exception_info_address)) {
    LOG(ERROR) << "Minidump generation failed.";
    base::DeleteFile(dump_file, false);
    return;
  }

  report_repository->StoreReport(dump_file, crash_keys);
}

// Implements kasko::Service to capture minidumps and store them in a
// ReportRepository.
class ServiceImpl : public Service {
  public:
   ServiceImpl(const base::FilePath& temporary_directory,
               ReportRepository* report_repository)
       : temporary_directory_(temporary_directory),
         report_repository_(report_repository) {}

   ~ServiceImpl() override {}

   // Service implementation.
   void SendDiagnosticReport(
       base::ProcessId client_process_id,
       uint64_t exception_info_address,
       base::PlatformThreadId thread_id,
       const char* protobuf,
       size_t protobuf_length,
       const std::map<base::string16, base::string16>& crash_keys) override {
     SendReportImpl(temporary_directory_, report_repository_, client_process_id,
                    exception_info_address, thread_id, protobuf,
                    protobuf_length, crash_keys);
   }

  private:
   base::FilePath temporary_directory_;
   ReportRepository* report_repository_;

   DISALLOW_COPY_AND_ASSIGN(ServiceImpl);
};

}  // namespace

const base::char16* const Reporter::kPermanentFailureCrashKeysExtension =
    L".kys";
const base::char16* const Reporter::kPermanentFailureMinidumpExtension =
    L".dmp";
const base::char16* const Reporter::kMinidumpUploadFilePart =
    L"upload_file_minidump";

// static
scoped_ptr<Reporter> Reporter::Create(
    const base::string16& endpoint_name,
    const base::string16& url,
    const base::FilePath& data_directory,
    const base::FilePath& permanent_failure_directory,
    const base::TimeDelta& upload_interval,
    const base::TimeDelta& retry_interval) {
  scoped_ptr<Reporter> instance(new Reporter(endpoint_name, url, data_directory,
                                             permanent_failure_directory,
                                             retry_interval));
  scoped_ptr<WaitableTimer> waitable_timer(
      WaitableTimerImpl::Create(upload_interval));
  if (!waitable_timer) {
    LOG(ERROR) << "Failed to create a timer for the upload process.";
    return scoped_ptr<Reporter>();
  }
  // It's safe to pass an Unretained reference to |report_repository_| because
  // |instance| will shut down |upload_thread_| before destroying
  // |report_repository_|..
  instance->upload_thread_ = UploadThread::Create(
      data_directory, waitable_timer.Pass(),
      base::Bind(base::IgnoreResult(&ReportRepository::UploadPendingReport),
                 base::Unretained(&instance->report_repository_)));

  if (!instance->upload_thread_) {
    LOG(ERROR) << "Failed to initialize background upload process.";
    return scoped_ptr<Reporter>();
  }

  if (!instance->service_bridge_.Run()) {
    LOG(ERROR) << "Failed to start the Kasko RPC service using protocol "
               << kRpcProtocol << " and endpoint name " << endpoint_name << ".";
    return scoped_ptr<Reporter>();
  }

  instance->upload_thread_->Start();

  return instance.Pass();
}

Reporter::~Reporter() {}

void Reporter::SendReportForProcess(
    base::ProcessHandle process_handle,
    const std::map<base::string16, base::string16>& crash_keys) {
  SendReportImpl(temporary_minidump_directory_, &report_repository_,
                 base::GetProcId(process_handle), NULL, 0, NULL, 0, crash_keys);
}

// static
void Reporter::Shutdown(scoped_ptr<Reporter> instance) {
  instance->upload_thread_->Stop();  // Non-blocking.
  instance->service_bridge_.Stop();  // Blocking.
  instance->upload_thread_->Join();  // Blocking.
}

Reporter::Reporter(const base::string16& endpoint_name,
                   const base::string16& url,
                   const base::FilePath& data_directory,
                   const base::FilePath& permanent_failure_directory,
                   const base::TimeDelta& retry_interval)
    : report_repository_(
          data_directory,
          retry_interval,
          base::Bind(&base::Time::Now),
          base::Bind(&UploadCrashReport, url),
          base::Bind(&HandlePermanentFailure, permanent_failure_directory)),
      temporary_minidump_directory_(
          base::FilePath(data_directory).Append(kTemporarySubdir)),
      service_bridge_(
          kRpcProtocol,
          endpoint_name,
          make_scoped_ptr(new ServiceImpl(temporary_minidump_directory_,
                                          &report_repository_))) {
}

}  // namespace kasko
