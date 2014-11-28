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

#ifndef SYZYGY_KASKO_HTTP_RESPONSE_H_
#define SYZYGY_KASKO_HTTP_RESPONSE_H_

#include <stdint.h>
#include "base/strings/string16.h"

namespace kasko {

// Provides access to the headers and content of the response to a previously
// issued HTTP request.
class HttpResponse {
 public:
  virtual ~HttpResponse() {}

  // Retrieves the response status code.
  // @param status_code Receives the status code.
  // @returns true if successful.
  virtual bool GetStatusCode(uint16_t* status_code) = 0;

  // Retrieves the specified content length, if any.
  // @param has_content_length Is set to true if the content length is
  //     specified.
  // @param content_length Receives the content length (if specified).
  // @returns true if the content length is retrieved or not specified in the
  //     response.
  virtual bool GetContentLength(bool* has_content_length,
                                size_t* content_length) = 0;

  // Retrieves the specified Content-Type header value, if any.
  // @param has_content_type Is set to true if the content type is
  //     specified.
  // @param content_type Receives the content type (if specified).
  // @returns true if the content type is retrieved or not specified in the
  //     response.
  virtual bool GetContentType(bool* has_content_type,
                              base::string16* content_type) = 0;

  // Checks the response body stream.
  // @param has_data Is set to true if data is available to read
  // @returns true if successful.
  virtual bool HasData(bool* has_data) = 0;

  // Reads from the response body stream.
  // @param buffer The location into which data will be read.
  // @param count On invocation, the maximum length to read into buffer. Upon
  //     successful return, the number of bytes read.
  // @returns true if successful.
  virtual bool ReadData(char* buffer, size_t* count) = 0;
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_HTTP_RESPONSE_H_
