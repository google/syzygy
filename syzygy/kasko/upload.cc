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

#include "base/logging.h"
#include "base/strings/utf_string_conversions.h"

#include "syzygy/common/com_utils.h"
#include "syzygy/kasko/http_agent.h"
#include "syzygy/kasko/http_response.h"
#include "syzygy/kasko/internet_helpers.h"

namespace kasko {

namespace {

// Reads up to |count| bytes of raw response body into |buffer|. Returns true if
// the entire response body is successfully read.
bool ReadResponseData(HttpResponse *response, char* buffer, size_t* count) {
  size_t content_length_header_value = 0;
  bool has_content_length_header = false;

  if (!response->GetContentLength(&has_content_length_header,
                                  &content_length_header_value)) {
    return false;
  }

  size_t total_read = 0;

  do {
    size_t single_read_count = *count - total_read;
    if (!response->ReadData(buffer + total_read, &single_read_count))
      return false;

    if (single_read_count == 0)
      break;

    total_read += single_read_count;
  } while (total_read < *count);

  bool has_more_data = false;
  if (!response->HasData(&has_more_data))
    return false;
  if (has_more_data) {
    LOG(ERROR) << "Incoming data exceeds anticipated maximum of " << *count
               << " bytes.";
    return false;
  }

  if (has_content_length_header &&
      (total_read != content_length_header_value)) {
    LOG(ERROR) << "Response body length of " << total_read
               << " differs from content length header value "
               << content_length_header_value;
    return false;
  }

  *count = total_read;
  return true;
}

// Reads and parses the Content-Type header from |response| and stores the
// resulting character set and MIME type in |charset| and |mime_type|. |charset|
// and |mime_type| will be empty if they are not present. Returns true if the
// header is absent or present and successfully parsed.
bool GetCharsetAndMimeType(HttpResponse* response,
                           base::string16* charset,
                           base::string16* mime_type) {
  base::string16 content_type;
  bool has_content_type = false;
  if (!response->GetContentType(&has_content_type, &content_type))
    return false;

  if (!has_content_type) {
    charset->clear();
    mime_type->clear();
    return true;
  }

  bool had_charset = false;
  base::string16 boundary;
  ParseContentType(content_type, mime_type, charset, &had_charset, &boundary);
  return true;
}

// Reads the response body and stores it in |response_body|. Does character set
// conversion if necessary. Returns true if the entire response body is
// successfully read.
bool ReadResponse(HttpResponse* response, base::string16 *response_body) {
  // We are only expecting a small identifier string.
  char buffer[256];
  size_t total_read = sizeof(buffer);
  if (!ReadResponseData(response, buffer, &total_read))
    return false;

  if (!response)
    return true;

  base::string16 charset, mime_type;
  if (!GetCharsetAndMimeType(response, &charset, &mime_type))
    return false;

  if (!mime_type.empty() && mime_type != L"text/plain") {
    LOG(ERROR) << "Unexpected MIME type: " << mime_type;
    return false;
  }

  if (charset.empty() || charset == L"utf-8") {
    *response_body = base::UTF8ToWide(base::StringPiece(buffer, total_read));
  } else if (charset == L"utf-16") {
    *response_body =
        base::string16(reinterpret_cast<const base::char16*>(buffer),
                       total_read / sizeof(base::char16));
  } else {
    LOG(ERROR) << "Unexpected charset: " << charset;
    return false;
  }

  return true;
}

}  // namespace

bool SendHttpUpload(HttpAgent* agent,
                    const base::string16& url,
                    const std::map<base::string16, base::string16>& parameters,
                    const std::string& upload_file,
                    const base::string16& file_part_name,
                    base::string16* response_body,
                    uint16_t* response_code) {
  if (response_code)
    *response_code = 0;

  base::string16 scheme, host, path;
  uint16_t port = 0;
  if (!DecomposeUrl(url, &scheme, &host, &port, &path)) {
    LOG(ERROR) << "Failed to decompose URL: " << url;
    return false;
  }

  bool secure = false;
  if (scheme == L"https") {
    secure = true;
  } else if (scheme != L"http") {
    LOG(ERROR) << "Invalid scheme in URL: " << url;
    return false;
  }

  base::string16 boundary = GenerateMultipartHttpRequestBoundary();
  base::string16 content_type_header =
      GenerateMultipartHttpRequestContentTypeHeader(boundary);

  std::string request_body = GenerateMultipartHttpRequestBody(
      parameters, upload_file, file_part_name, boundary);

  scoped_ptr<HttpResponse> response =
      agent->Post(host, port, path, secure, content_type_header, request_body);
  if (!response) {
    LOG(ERROR) << "Request to " << url << " failed.";
    return false;
  }

  uint16_t status_code = 0;
  if (!response->GetStatusCode(&status_code))
    return false;

  if (response_code)
    *response_code = status_code;

  if (status_code != 200) {
    LOG(ERROR) << "Request to " << url << " failed with HTTP status code "
               << status_code;
    return false;
  }

  return ReadResponse(response.get(), response_body);
}

}  // namespace kasko
