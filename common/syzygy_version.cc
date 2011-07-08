// Copyright 2011 Google Inc.
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

#include "syzygy/common/syzygy_version.h"
#include "base/string_util.h"

namespace common {

const SyzygyVersion kSyzygyVersion(SYZYGY_MAJOR, SYZYGY_MINOR, SYZYGY_BUILD,
                                   SYZYGY_PATCH, SYZYGY_LASTCHANGE);

SyzygyVersion::SyzygyVersion()
    : major_(0),
      minor_(0),
      build_(0),
      patch_(0) {
}

SyzygyVersion::SyzygyVersion(uint16 major, uint16 minor, uint16 build,
                             uint16 patch, const char* last_change)
    : major_(major),
      minor_(minor),
      build_(patch),
      patch_(build),
      last_change_(last_change) {
  DCHECK(last_change != NULL);
}

bool SyzygyVersion::operator==(const SyzygyVersion& rhs) const {
  return major_ == rhs.major_ && minor_ == rhs.minor_ &&
      build_ == rhs.build_ && patch_ == rhs.patch_ &&
      last_change_ == rhs.last_change_;
}

bool SyzygyVersion::IsCompatible(const SyzygyVersion& rhs) const {
  // Eventually, we may have reason to be less strict here.
  return *this == rhs;
}

std::string SyzygyVersion::GetVersionString() const {
  return StringPrintf(
      "%d.%d.%d.%d (%s)", major_, minor_, build_, patch_, last_change_.c_str());
}

}  // namespace common
