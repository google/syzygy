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
//
// Version defines.
#ifndef SYZYGY_COMMON_SYZYGY_VERSION_H_
#define SYZYGY_COMMON_SYZYGY_VERSION_H_

#include <string>
#include "base/basictypes.h"
#include "base/logging.h"
#include "version.gen"  // NOLINT

namespace common {

class SyzygyVersion {
 public:
  SyzygyVersion();

  SyzygyVersion(uint16 major, uint16 minor, uint16 build, uint16 patch,
                const char* last_change);

  bool operator==(const SyzygyVersion& rhs) const;

  uint16 major() const { return major_; }
  uint16 minor() const { return minor_; }
  uint16 build() const { return build_; }
  uint16 patch() const { return patch_; }
  const std::string& last_change() const { return last_change_; }

  // For serialization.
  template<class OutArchive> bool Save(OutArchive* out_archive) const {
    DCHECK(out_archive != NULL);
    return out_archive->Save(major_) && out_archive->Save(minor_) &&
        out_archive->Save(build_) && out_archive->Save(patch_) &&
        out_archive->Save(last_change_);
  }
  template<class InArchive> bool Load(InArchive* in_archive) {
    DCHECK(in_archive != NULL);
    return in_archive->Load(&major_) && in_archive->Load(&minor_) &&
        in_archive->Load(&build_) && in_archive->Load(&patch_) &&
        in_archive->Load(&last_change_);
  }

 private:
  uint16 major_;
  uint16 minor_;
  uint16 build_;
  uint16 patch_;
  std::string last_change_;
};

extern const SyzygyVersion kSyzygyVersion;

}  // namespace common

#endif  // SYZYGY_COMMON_SYZYGY_VERSION_H_
