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

#ifndef SYZYGY_KASKO_INTERNET_UNITTEST_HELPERS_H_
#define SYZYGY_KASKO_INTERNET_UNITTEST_HELPERS_H_

#include <map>
#include <string>

#include "base/strings/string16.h"

namespace kasko {

// Verifies that the supplied multipart MIME message body is plausibly
// formatted. Adds non-fatal GTest failures if verification fails.
// @param boundary The boundary specified in the Content-Type header that
//     accompanied the body.
// @param parameters The parameters that are expected to be encoded in the body.
// @param file The file contents that are expdected to be encoded in the body.
// @param file_part_name The name expected to be assigned to the file parameter.
void ExpectMultipartMimeMessageIsPlausible(
    const base::string16& boundary,
    const std::map<base::string16, base::string16>& parameters,
    const std::string& file,
    const std::string& file_part_name,
    const std::string& body);

}  // namespace kasko

#endif  // SYZYGY_KASKO_INTERNET_UNITTEST_HELPERS_H_
