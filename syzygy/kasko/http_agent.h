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

#ifndef SYZYGY_KASKO_HTTP_AGENT_H_
#define SYZYGY_KASKO_HTTP_AGENT_H_

#include <stdint.h>
#include <memory>
#include <string>

#include "base/strings/string16.h"

namespace kasko {

class HttpResponse;

// Defines an interface for issuing HTTP requests.
class HttpAgent {
 public:
  virtual ~HttpAgent() {}

  // Issues an HTTP POST request.
  // @param host The target host.
  // @param port The target port.
  // @param path The resource path.
  // @param secure Whether to use HTTPS.
  // @param extra_headers Zero or more CRLF-delimited HTTP header lines to
  //     include in the request.
  // @param body The request body.
  // @returns NULL if the request fails for any reason. Otherwise, returns an
  //     HttpResponse that may be used to access the HTTP response.
  virtual std::unique_ptr<HttpResponse> Post(
      const base::string16& host,
      uint16_t port,
      const base::string16& path,
      bool secure,
      const base::string16& extra_headers,
      const std::string& body) = 0;
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_HTTP_AGENT_H_
