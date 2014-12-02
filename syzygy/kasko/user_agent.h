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

#ifndef SYZYGY_KASKO_USER_AGENT_H_
#define SYZYGY_KASKO_USER_AGENT_H_

#include <stdint.h>
#include "base/macros.h"
#include "base/strings/string16.h"

namespace kasko {

// Collects the various properties that go into the Kasko user-agent string and
// formats them.
class UserAgent {
 public:
  enum Architecture { X86, WOW64, X64, IA64 };

  // Creates a default-initialized instance. This does not query platform
  // attributes. The client must do so.
  // @param product_name The product name.
  // @param product_version The product version.
  UserAgent(const base::string16& product_name,
            const base::string16& product_version);
  ~UserAgent();

  // @returns A string suitable for use as the value of a User-Agent header, and
  //     incorporating the various properties of this class.
  base::string16 AsString();

  // Sets the OS version.
  // @param major_version The OS major version number.
  // @param minor_version The OS minor version number.
  void set_os_version(int32_t major_version, int32_t minor_version) {
    os_major_version_ = major_version;
    os_minor_version_ = minor_version;
  }

  // Sets the platform architecture.
  // @param architecture The platform architecture.
  void set_architecture(Architecture architecture) {
    architecture_ = architecture;
  }

  // Sets the WinHttp library version.
  // @winhttp_version The WinHttp library version.
  void set_winhttp_version(const base::string16& winhttp_version) {
    winhttp_version_ = winhttp_version;
  }

 private:
  base::string16 product_name_;
  base::string16 product_version_;
  int32_t os_major_version_;
  int32_t os_minor_version_;
  Architecture architecture_;
  base::string16 winhttp_version_;

  DISALLOW_COPY_AND_ASSIGN(UserAgent);
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_USER_AGENT_H_
