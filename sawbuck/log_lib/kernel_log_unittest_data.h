// Copyright 2010 Google Inc.
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
#ifndef SAWBUCK_LOG_LIB_KERNEL_LOG_UNITTEST_DATA_H_
#define SAWBUCK_LOG_LIB_KERNEL_LOG_UNITTEST_DATA_H_

#include "sawbuck/sym_util/types.h"
#include "sawbuck/log_lib/kernel_log_consumer.h"

namespace testing {

extern const sym_util::ModuleInformation module_list[];
extern const size_t kNumModules;

extern const KernelProcessEvents::ProcessInfo process_list[];
extern const size_t kNumProcesses;

}  // namespace testing

#endif  // SAWBUCK_LOG_LIB_KERNEL_LOG_UNITTEST_DATA_H_
