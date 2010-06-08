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

#include "base/logging.h"

namespace sym_util {

bool ModuleInformation::operator < (const ModuleInformation& o) const {
  if (base_address < o.base_address)
    return true;
  if (base_address > o.base_address)
    return false;
  DCHECK(base_address == o.base_address);

  if (module_size < o.module_size)
    return true;
  if (module_size > o.module_size)
    return false;
  DCHECK(module_size == o.module_size);

  if (image_checksum < o.image_checksum)
    return true;
  if (image_checksum > o.image_checksum)
    return false;
  DCHECK(image_checksum == o.image_checksum);

  if (time_date_stamp < o.time_date_stamp)
    return true;
  if (time_date_stamp > o.time_date_stamp)
    return false;
  DCHECK(time_date_stamp == o.time_date_stamp);

  return image_file_name < o.image_file_name;
}

bool ModuleInformation::operator == (const ModuleInformation& o) const {
  return base_address == o.base_address &&
         module_size == o.module_size &&
         image_checksum == o.image_checksum &&
         time_date_stamp == o.time_date_stamp &&
         image_file_name == o.image_file_name;
}

}  // namespace sym_util
