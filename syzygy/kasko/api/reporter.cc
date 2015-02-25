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

#include "base/logging.h"
#include "base/files/file_path.h"
#include "base/memory/scoped_ptr.h"
#include "base/time/time.h"
#include "syzygy/kasko/dll_lifetime.h"
#include "syzygy/kasko/reporter.h"

namespace kasko {
namespace api {
namespace {

const uint16_t kUploadDelayInSeconds = 180;
const uint16_t kRetryIntevalInMinutes = 180;

const DllLifetime* g_dll_lifetime;
Reporter* g_reporter;

}  // namespace

const base::char16* const kPermanentFailureCrashKeysExtension =
    Reporter::kPermanentFailureCrashKeysExtension;
const base::char16* const kPermanentFailureMinidumpExtension =
    Reporter::kPermanentFailureMinidumpExtension;

bool InitializeReporter(
    const base::char16* endpoint_name,
    const base::char16* url,
    const base::char16* data_directory,
    const base::char16* permanent_failure_directory) {
  DCHECK(!g_dll_lifetime);
  g_dll_lifetime = new DllLifetime;

  DCHECK(!g_reporter);
  g_reporter =
      Reporter::Create(endpoint_name, url, base::FilePath(data_directory),
                       base::FilePath(permanent_failure_directory),
                       base::TimeDelta::FromSeconds(kUploadDelayInSeconds),
                       base::TimeDelta::FromMinutes(kRetryIntevalInMinutes))
          .release();
  return g_reporter != nullptr;
}

void SendReportForProcess(base::ProcessHandle process_handle,
                          const base::char16* const* keys,
                          const base::char16* const* values) {
  DCHECK(g_reporter);
  if (!g_reporter)
    return;
  DCHECK_EQ(keys == nullptr, values == nullptr);

  std::map<base::string16, base::string16> crash_keys;
  if (keys != nullptr && values != nullptr) {
    size_t i = 0;
    for (; keys[i] && values[i]; ++i) {
      crash_keys[keys[i]] = values[i];
    }
    DCHECK(!keys[i]);
    DCHECK(!values[i]);
  }

  g_reporter->SendReportForProcess(process_handle, crash_keys);
}

void ShutdownReporter() {
  scoped_ptr<Reporter> reporter(g_reporter);
  g_reporter = nullptr;
  Reporter::Shutdown(reporter.Pass());

  DCHECK(g_dll_lifetime);
  delete g_dll_lifetime;
  g_dll_lifetime = nullptr;
}

}  // namespace api
}  // namespace kasko
