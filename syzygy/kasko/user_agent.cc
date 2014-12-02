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

#include "syzygy/kasko/user_agent.h"

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"

namespace kasko {

namespace {

const base::char16* ArchitectureToString(UserAgent::Architecture architecture) {
  switch (architecture) {
    case UserAgent::WOW64:
      return L"; WOW64";
    case UserAgent::X64:
      return L"; Win64; x64";
    case UserAgent::IA64:
      return L"; Win64; IA64";
    case UserAgent::X86:
      return L"";
    default:
      NOTREACHED();
      return L"";
  }
}

}  // namespace

UserAgent::UserAgent(const base::string16& product_name,
                     const base::string16& product_version)
    : product_name_(product_name),
      product_version_(product_version),
      os_major_version_(0),
      os_minor_version_(0),
      architecture_(X86) {
}

UserAgent::~UserAgent() {
}

base::string16 UserAgent::AsString() {
  return product_name_ + L"/" + product_version_ + L" (Windows NT " +
         base::IntToString16(os_major_version_) + L"." +
         base::IntToString16(os_minor_version_) +
         ArchitectureToString(architecture_) + L") WinHTTP/" + winhttp_version_;
}

}  // namespace kasko
