// Copyright 2009 Google Inc.
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
#include "sawbuck/sym_util/types.h"

namespace sym_util {

bool ModuleInformation::operator < (const ModuleInformation& o) const {
  if (image_file_name < o.image_file_name)
    return true;
  if (image_file_name == o.image_file_name) {
    // Do a binary comparison of the two structures up to the name field
    // to define a somewhat arbitrary, but consistent, ordering on them.
    return memcmp(this,
                  &o,
                  FIELD_OFFSET(ModuleInformation, image_file_name)) < 0;
  }

  return false;
}

}  // namespace sym_util
