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
#include <memory>
#include <string>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback.h"
#include "base/logging.h"
#include "base/files/file_util.h"
#include "base/memory/ptr_util.h"
#include "base/process/process.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "syzygy/kasko/http_agent_impl.h"
#include "syzygy/kasko/minidump.h"
#include "syzygy/kasko/minidump_request.h"
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

void GenerateReport(const base::FilePath& temporary_directory,
                    ReportRepository* report_repository,
                    base::ProcessHandle client_process,
                    base::PlatformThreadId thread_id,
                    const MinidumpRequest& request) {
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

  if (!GenerateMinidump(dump_file, client_process, thread_id, request)) {
    LOG(ERROR) << "Minidump generation failed.";
    base::DeleteFile(dump_file, false);
    return;
  }

  std::map<base::string16, base::string16> crash_keys;
  for (auto& crash_key : request.crash_keys) {
    crash_keys[crash_key.first] = crash_key.second;
  }

  crash_keys[Reporter::kKaskoGeneratedByVersion] =
      base::ASCIIToUTF16(KASKO_VERSION_STRING);

  report_repository->StoreReport(dump_file, crash_keys);
}

// Implements kasko::Service to capture minidumps and store them in a
// ReportRepository.
class ServiceImpl : public Service {
 public:
  ServiceImpl(const base::FilePath& temporary_directory,
              ReportRepository* report_repository,
              UploadThread* upload_thread)
      : temporary_directory_(temporary_directory),
        report_repository_(report_repository),
        upload_thread_(upload_thread) {}

  ~ServiceImpl() override {}

  // Service implementation.
  void SendDiagnosticReport(base::ProcessId client_process_id,
                            base::PlatformThreadId thread_id,
                            const MinidumpRequest& request) override {
    base::win::ScopedHandle client_process(
        ::OpenProcess(GetRequiredAccessForMinidumpType(request.type), FALSE,
                      client_process_id));
    if (client_process.IsValid()) {
      GenerateReport(temporary_directory_, report_repository_,
                     client_process.Get(), thread_id, request);
    }
    upload_thread_->UploadOneNowAsync();
  }

 private:
  base::FilePath temporary_directory_;
  ReportRepository* report_repository_;
  UploadThread* upload_thread_;

  DISALLOW_COPY_AND_ASSIGN(ServiceImpl);
};

}  // namespace

const base::char16* const Reporter::kPermanentFailureCrashKeysExtension =
    L".kys";
const base::char16* const Reporter::kPermanentFailureMinidumpExtension =
    L".dmp";
const base::char16* const Reporter::kMinidumpUploadFilePart =
    L"upload_file_minidump";
const base::char16* const Reporter::kKaskoGeneratedByVersion =
    L"kasko-generated-by-version";
const base::char16* const Reporter::kKaskoUploadedByVersion =
    L"kasko-uploaded-by-version";

// static
std::unique_ptr<Reporter> Reporter::Create(
    const base::string16& endpoint_name,
    const base::string16& url,
    const base::FilePath& data_directory,
    const base::FilePath& permanent_failure_directory,
    const base::TimeDelta& upload_interval,
    const base::TimeDelta& retry_interval,
    const OnUploadCallback& on_upload_callback) {
  std::unique_ptr<WaitableTimer> waitable_timer(
      WaitableTimerImpl::Create(upload_interval));
  if (!waitable_timer) {
    LOG(ERROR) << "Failed to create a timer for the upload process.";
    return std::unique_ptr<Reporter>();
  }

  std::unique_ptr<ReportRepository> report_repository(new ReportRepository(
      data_directory, retry_interval, base::Bind(&base::Time::Now),
      base::Bind(&UploadCrashReport, on_upload_callback, url),
      base::Bind(&HandlePermanentFailure, permanent_failure_directory)));

  // It's safe to pass an Unretained reference to |report_repository| because
  // the Reporter instance will shut down |upload_thread| before destroying
  // |report_repository|.
  std::unique_ptr<UploadThread> upload_thread = UploadThread::Create(
      data_directory, std::move(waitable_timer),
      base::Bind(base::IgnoreResult(&ReportRepository::UploadPendingReport),
                 base::Unretained(report_repository.get())));

  if (!upload_thread) {
    LOG(ERROR) << "Failed to initialize background upload process.";
    return std::unique_ptr<Reporter>();
  }

  std::unique_ptr<Reporter> instance(
      new Reporter(std::move(report_repository), std::move(upload_thread),
                   endpoint_name, data_directory.Append(kTemporarySubdir)));
  if (!instance->service_bridge_.Run()) {
    LOG(ERROR) << "Failed to start the Kasko RPC service using protocol "
               << kRpcProtocol << " and endpoint name " << endpoint_name << ".";
    return std::unique_ptr<Reporter>();
  }

  instance->upload_thread_->Start();

  return std::move(instance);
}

Reporter::~Reporter() {}

void Reporter::SendReportForProcess(base::ProcessHandle process_handle,
                                    base::PlatformThreadId thread_id,
                                    MinidumpRequest request) {
  GenerateReport(temporary_minidump_directory_, report_repository_.get(),
                 process_handle, thread_id, request);
  upload_thread_->UploadOneNowAsync();
}

// static
void Reporter::Shutdown(std::unique_ptr<Reporter> instance) {
  instance->upload_thread_->Stop();  // Non-blocking.
  instance->service_bridge_.Stop();  // Blocking.
  instance->upload_thread_->Join();  // Blocking.
}

// static
bool Reporter::UploadCrashReport(
    const Reporter::OnUploadCallback& on_upload_callback,
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
  std::map<base::string16, base::string16> augmented_crash_keys(crash_keys);
  augmented_crash_keys[Reporter::kKaskoUploadedByVersion] =
      base::ASCIIToUTF16(KASKO_VERSION_STRING);
  if (!SendHttpUpload(&http_agent, upload_url, augmented_crash_keys,
                      dump_contents, Reporter::kMinidumpUploadFilePart,
                      &remote_dump_id, &response_code)) {
    LOG(ERROR) << "Failed to upload the minidump file to " << upload_url;
    return false;
  } else if (!on_upload_callback.is_null()) {
    on_upload_callback.Run(remote_dump_id, minidump_path, crash_keys);
  }

  return true;
}

Reporter::Reporter(std::unique_ptr<ReportRepository> report_repository,
                   std::unique_ptr<UploadThread> upload_thread,
                   const base::string16& endpoint_name,
                   const base::FilePath& temporary_minidump_directory)
    : report_repository_(std::move(report_repository)),
      upload_thread_(std::move(upload_thread)),
      temporary_minidump_directory_(temporary_minidump_directory),
      service_bridge_(
          kRpcProtocol,
          endpoint_name,
          base::WrapUnique(new ServiceImpl(temporary_minidump_directory_,
                                           report_repository_.get(),
                                           upload_thread_.get()))) {
}

}  // namespace kasko
