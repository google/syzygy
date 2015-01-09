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
#include "syzygy/kasko/reporter.h"

namespace kasko {
namespace api {
namespace {

const uint16_t kUploadDelayInSeconds = 180;
const uint16_t kRetryIntevalInMinutes = 180;

Reporter* g_reporter;

}  // namespace

bool InitializeReporter(
    const base::char16* endpoint_name,
    const base::char16* url,
    const base::char16* data_directory,
    const base::char16* permanent_failure_directory) {
  DCHECK(!g_reporter);

  g_reporter =
      Reporter::Create(endpoint_name, url, base::FilePath(data_directory),
                       base::FilePath(permanent_failure_directory),
                       base::TimeDelta::FromSeconds(kUploadDelayInSeconds),
                       base::TimeDelta::FromMinutes(kRetryIntevalInMinutes))
          .release();
  return g_reporter != nullptr;
}

void ShutdownReporter() {
  scoped_ptr<Reporter> reporter(g_reporter);
  g_reporter = NULL;
  Reporter::Shutdown(reporter.Pass());
}

}  // namespace api
}  // namespace kasko
