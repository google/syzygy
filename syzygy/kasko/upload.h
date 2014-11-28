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

#ifndef SYZYGY_KASKO_UPLOAD_H_
#define SYZYGY_KASKO_UPLOAD_H_

#include <stdint.h>
#include <map>
#include <string>

#include "base/strings/string16.h"

namespace kasko {

class HttpAgent;

// POSTs a multipart MIME message via HTTP(S).
// @param agent The HTTP implementation to use.
// @param url The resource to which to POST.
// @param parameters HTTP request parameters to be encoded in the body.
// @param upload_file File contents to be encoded in the body.
// @param file_part_name The parameter name to be assigned to the file part.
// @param response_body Receives the HTTP response body.
// @param response_code Receives the HTTP response status code.
// @returns true if successful.
bool SendHttpUpload(HttpAgent* agent,
                    const base::string16& url,
                    const std::map<base::string16, base::string16>& parameters,
                    const std::string& upload_file,
                    const base::string16& file_part_name,
                    base::string16* response_body,
                    uint16_t* response_code);

}  // namespace kasko

#endif  // SYZYGY_KASKO_UPLOAD_H_
