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

#include "syzygy/kasko/api/reporter.h"

#include <stdint.h>

#include <map>
#include <memory>
#include <vector>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/environment.h"
#include "base/logging.h"
#include "base/files/file_path.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/time.h"
#include "base/win/scoped_handle.h"
#include "syzygy/kasko/dll_lifetime.h"
#include "syzygy/kasko/minidump.h"
#include "syzygy/kasko/minidump_request.h"
#include "syzygy/kasko/reporter.h"
#include "syzygy/kasko/api/crash_key.h"
#include "syzygy/kasko/api/internal/crash_key_registration.h"

namespace kasko {
namespace api {
namespace {

// Default upload and retry times. These can be overridden by an environment
// variable.
const uint16_t kDefaultUploadDelayInSeconds = 180;
const uint16_t kDefaultRetryIntervalInMinutes = 180;

// Environment variables for overriding the above times.
const char kEnvUploadDelayInSeconds[] = "KASKO_UPLOAD_DELAY_IN_SECONDS";
const char kEnvRetryIntervalInMinutes[] = "KASKO_RETRY_INTERVAL_IN_MINUTES";

const DllLifetime* g_dll_lifetime;
Reporter* g_reporter;

void InvokeOnUploadProc(
    OnUploadProc* on_upload_proc,
    void* on_upload_context,
    const base::string16& report_id,
    const base::FilePath& minidump_path,
    const std::map<base::string16, base::string16>& crash_keys) {
  std::vector<const base::char16*> crash_key_names;
  std::vector<const base::char16*> crash_key_values;
  crash_key_names.reserve(crash_keys.size() + 1);
  crash_key_values.reserve(crash_keys.size() + 1);

  for (const auto& entry : crash_keys) {
    crash_key_names.push_back(entry.first.c_str());
    crash_key_values.push_back(entry.second.c_str());
  }
  crash_key_names.push_back(nullptr);
  crash_key_values.push_back(nullptr);

  on_upload_proc(on_upload_context, report_id.c_str(),
                 minidump_path.value().c_str(), crash_key_names.data(),
                 crash_key_values.data());
}

// Returns an integer value from the environment. If not present or malformed,
// returns the specified default. Only allows positive values.
int64_t GetIntegerFromEnvironment(const char* key_name,
                                  int64_t default_value) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  std::string value;
  if (!env->GetVar(key_name, &value))
    return default_value;

  int64_t i = 0;
  if (!base::StringToInt64(value, &i))
    return default_value;

  if (i <= 0)
    return default_value;

  return i;
}

}  // namespace

const base::char16* const kPermanentFailureCrashKeysExtension =
    Reporter::kPermanentFailureCrashKeysExtension;
const base::char16* const kPermanentFailureMinidumpExtension =
    Reporter::kPermanentFailureMinidumpExtension;

bool InitializeReporter(const base::char16* endpoint_name,
                        const base::char16* url,
                        const base::char16* data_directory,
                        const base::char16* permanent_failure_directory,
                        OnUploadProc* on_upload_proc,
                        void* on_upload_context) {
  DCHECK(!g_dll_lifetime);
  g_dll_lifetime = new DllLifetime;

  Reporter::OnUploadCallback on_upload_callback;

  if (on_upload_proc) {
    on_upload_callback =
        base::Bind(&InvokeOnUploadProc, base::Unretained(on_upload_proc),
                   base::Unretained(on_upload_context));
  }


  int64_t upload_delay = GetIntegerFromEnvironment(
      kEnvUploadDelayInSeconds, kDefaultUploadDelayInSeconds);
  int64_t retry_interval = GetIntegerFromEnvironment(
      kEnvRetryIntervalInMinutes, kDefaultRetryIntervalInMinutes);
  DCHECK(!g_reporter);
  g_reporter =
      Reporter::Create(endpoint_name, url, base::FilePath(data_directory),
                       base::FilePath(permanent_failure_directory),
                       base::TimeDelta::FromSeconds(upload_delay),
                       base::TimeDelta::FromMinutes(retry_interval),
                       on_upload_callback)
          .release();

  return g_reporter != nullptr;
}

void SendReportForProcess(base::ProcessHandle process_handle,
                          base::PlatformThreadId thread_id,
                          const EXCEPTION_POINTERS* exception_pointers,
                          MinidumpType minidump_type,
                          const base::char16* const* keys,
                          const base::char16* const* values) {
  DCHECK(g_reporter);
  if (!g_reporter)
    return;
  DCHECK_EQ(keys == nullptr, values == nullptr);

  MinidumpRequest request;

  request.exception_info_address =
      reinterpret_cast<uint32_t>(exception_pointers);

  if (keys != nullptr && values != nullptr) {
    size_t i = 0;
    for (; keys[i] && values[i]; ++i) {
      if (keys[i][0] == 0 || values[i][0] == 0)
        continue;
      request.crash_keys.push_back(
          MinidumpRequest::CrashKey(keys[i], values[i]));
    }
    DCHECK(!keys[i]);
    DCHECK(!values[i]);
  }

  // Reopen the process handle with the necessary access level to read memory
  // and create a minidump.
  base::win::ScopedHandle augmented_process_handle(
      ::OpenProcess(GetRequiredAccessForMinidumpType(minidump_type), FALSE,
                    base::GetProcId(process_handle)));
  if (!augmented_process_handle.IsValid())
    return;

  std::vector<CrashKey> registered_crash_keys;
  if (internal::ReadCrashKeysFromProcess(augmented_process_handle.Get(),
                                         &registered_crash_keys)) {
    for (auto& crash_key : registered_crash_keys) {
      if (crash_key.name[0] == 0 || crash_key.value[0] == 0)
        continue;
      request.crash_keys.push_back(
          MinidumpRequest::CrashKey(crash_key.name, crash_key.value));
    }
  }

  switch (minidump_type) {
    case SMALL_DUMP_TYPE:
      request.type = MinidumpRequest::SMALL_DUMP_TYPE;
      break;
    case LARGER_DUMP_TYPE:
      request.type = MinidumpRequest::LARGER_DUMP_TYPE;
      break;
    case FULL_DUMP_TYPE:
      request.type = MinidumpRequest::FULL_DUMP_TYPE;
      break;
    default:
      NOTREACHED();
      break;
  }

  g_reporter->SendReportForProcess(augmented_process_handle.Get(), thread_id,
                                   request);
}

void ShutdownReporter() {
  std::unique_ptr<Reporter> reporter(g_reporter);
  g_reporter = nullptr;
  Reporter::Shutdown(std::move(reporter));

  DCHECK(g_dll_lifetime);
  delete g_dll_lifetime;
  g_dll_lifetime = nullptr;
}

}  // namespace api
}  // namespace kasko
