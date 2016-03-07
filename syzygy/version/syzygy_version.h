// Copyright 2011 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_VERSION_SYZYGY_VERSION_H_
#define SYZYGY_VERSION_SYZYGY_VERSION_H_

#include <stdint.h>
#include <string>

#include "base/logging.h"
#include "syzygy/version/version.gen"

namespace version {

class SyzygyVersion {
 public:
  SyzygyVersion();

  SyzygyVersion(uint16_t major,
                uint16_t minor,
                uint16_t build,
                uint16_t patch,
                const char* last_change);

  // A comparison operator. If this version is less than @p rhs, returns a value
  // less than zero. If identical, returns 0. If greater than @p rhs, returns a
  // value greater than 0. This only compares the version octet, ignoring the
  // last-change string.
  int CompareOctet(const SyzygyVersion& rhs) const;

  // We need an equality operator for serialization testing. This uses strict
  // equality, including a comparison of the last change string.
  bool operator==(const SyzygyVersion& rhs) const;
  bool operator!=(const SyzygyVersion& rhs) const { return !(*this == rhs); }

  // This returns true if the data/modules created by the given version of the
  // toolchain are compatible with this version of the toolchain. For now, this
  // returns true iff the two versions are completely identical, including the
  // last-change string.
  bool IsCompatible(const SyzygyVersion& rhs) const;

  // Returns the whole version as a version string.
  std::string GetVersionString() const;

  uint16_t major() const { return major_; }
  uint16_t minor() const { return minor_; }
  uint16_t build() const { return build_; }
  uint16_t patch() const { return patch_; }
  const std::string& last_change() const { return last_change_; }

  void set_major(uint16_t major) { major_ = major; }
  void set_minor(uint16_t minor) { minor_ = minor; }
  void set_build(uint16_t build) { build_ = build; }
  void set_patch(uint16_t patch) { patch_ = patch; }
  void set_last_change(const char* last_change) {
    DCHECK(last_change != NULL);
    last_change_ = last_change;
  }

  // For serialization. These are kept templated to remove any dependency
  // on core_lib, where serialization lives.
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
  uint16_t major_;
  uint16_t minor_;
  uint16_t build_;
  uint16_t patch_;
  std::string last_change_;
};

extern const SyzygyVersion kSyzygyVersion;

}  // namespace version

#endif  // SYZYGY_VERSION_SYZYGY_VERSION_H_
