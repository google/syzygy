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

#ifndef SYZYGY_KASKO_API_MINIDUMP_TYPE_H_
#define SYZYGY_KASKO_API_MINIDUMP_TYPE_H_

namespace kasko {
namespace api {

// Specifies the type of Minidump to be included in a report.
enum MinidumpType {
  // Minidump with stacks, PEB, TEB, and unloaded module list.
  SMALL_DUMP_TYPE,

  // Minidump with all of the above, plus memory referenced from stack.
  LARGER_DUMP_TYPE,

  // Large dump with all process memory.
  FULL_DUMP_TYPE
};

}  // namespace api
}  // namespace kasko

#endif  // SYZYGY_KASKO_API_MINIDUMP_TYPE_H_
