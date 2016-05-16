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

#include "syzygy/kasko/upload.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <memory>
#include <queue>
#include <string>
#include <vector>

#include "base/macros.h"
#include "base/strings/string16.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"
#include "syzygy/kasko/http_agent.h"
#include "syzygy/kasko/http_response.h"
#include "syzygy/kasko/internet_helpers.h"
#include "syzygy/kasko/internet_unittest_helpers.h"

namespace kasko {

namespace {

// An implementation of HttpAgent that performs a sanity check on the request
// parameters before returning a fixed HttpResponse.
class MockHttpAgent : public HttpAgent {
 public:
  // Defines the expected request parameters.
  struct Expectations {
    base::string16 host;
    uint16_t port;
    base::string16 path;
    bool secure;
    std::map<base::string16, base::string16> parameters;
    std::string file;
    base::string16 file_name;
  };

  MockHttpAgent();
  ~MockHttpAgent() override;

  Expectations& expectations();
  void set_response(std::unique_ptr<HttpResponse> response);
  void set_expect_invocation(bool expect_invocation) {
    invoked_ = !expect_invocation;
  }

  // HttpAgent implementation
  std::unique_ptr<HttpResponse> Post(const base::string16& host,
                                     uint16_t port,
                                     const base::string16& path,
                                     bool secure,
                                     const base::string16& extra_headers,
                                     const std::string& body) override;

 private:
  Expectations expectations_;
  std::unique_ptr<HttpResponse> response_;
  bool invoked_;

  DISALLOW_COPY_AND_ASSIGN(MockHttpAgent);
};

MockHttpAgent::MockHttpAgent() : invoked_(false) {
}

MockHttpAgent::~MockHttpAgent() {
  EXPECT_TRUE(invoked_);
}

MockHttpAgent::Expectations& MockHttpAgent::expectations() {
  return expectations_;
}

void MockHttpAgent::set_response(std::unique_ptr<HttpResponse> response) {
  response_ = std::move(response);
}

std::unique_ptr<HttpResponse> MockHttpAgent::Post(
    const base::string16& host,
    uint16_t port,
    const base::string16& path,
    bool secure,
    const base::string16& extra_headers,
    const std::string& body) {
  EXPECT_FALSE(invoked_);
  invoked_ = true;
  EXPECT_EQ(expectations_.host, host);
  EXPECT_EQ(expectations_.port, port);
  EXPECT_EQ(expectations_.path, path);
  EXPECT_EQ(expectations_.secure, secure);

  base::string16 boundary;

  base::StringTokenizerT<base::string16, base::string16::const_iterator>
      tokenizer(extra_headers.begin(), extra_headers.end(), L":");
  if (!tokenizer.GetNext()) {
    ADD_FAILURE() << "Failed to parse Content-Type from extra headers: "
                  << extra_headers;
  } else {
    EXPECT_EQ(L"content-type", base::ToLowerASCII(tokenizer.token()));
    if (!tokenizer.GetNext()) {
      ADD_FAILURE() << "Failed to parse Content-Type value from extra headers: "
                    << extra_headers;
    } else {
      base::string16 mime_type, charset;
      bool had_charset = false;
      // Use extra_headers.end() since we don't want to choke on a theoretical :
      // embedded in the value.
      ParseContentType(
          base::string16(tokenizer.token_begin(), extra_headers.end()),
          &mime_type, &charset, &had_charset, &boundary);
    }
  }

  EXPECT_FALSE(boundary.empty());

  ExpectMultipartMimeMessageIsPlausible(
      boundary, expectations_.parameters, expectations_.file,
      base::WideToUTF8(expectations_.file_name), body);

  EXPECT_EQ(expectations_.host, host);

  return std::move(response_);
}

// An implementation of HttpResponse that may be configured to fail at any point
// and to serve a response in a configurable series of packets.
class MockHttpResponse : public HttpResponse {
 public:
  MockHttpResponse();

  // HttpResponse implementation
  bool GetStatusCode(uint16_t* status_code) override;
  bool GetContentLength(bool* has_content_length,
                        size_t* content_length) override;
  bool GetContentType(bool* has_content_type,
                      base::string16* content_type) override;
  bool HasData(bool* has_data) override;
  bool ReadData(char* buffer, size_t* count) override;

  // Sets the values that will be returned by GetStatusCode().
  void set_status_code(bool success, uint16_t status_code);

  // Sets the values that will be returned by GetContentLength();
  void set_content_length(bool success,
                          bool has_content_length,
                          size_t content_length);

  // Sets the values that will be returned by GetContentType();
  void set_content_type(bool success,
                        bool has_content_type,
                        base::string16 content_type);

  // Configures the behaviour of HasData() and ReadData(). Each element in
  // |data| will be treated as a packet. Calls to ReadData() will consume all or
  // part of the current packet. HasData() will return true if there are
  // remaining packets. An empty element in |data| will signal the successful
  // completion of the data stream. If, after consuming all elements in |data|,
  // no empty packet is found, a read error will be simulated (ReadData() and
  // HasData() will both return false).
  void set_data(const std::vector<std::string>& data);

 private:
  bool status_code_success_;
  uint16_t status_code_;
  bool content_length_success_;
  bool has_content_length_;
  size_t content_length_;
  bool content_type_success_;
  bool has_content_type_;
  base::string16 content_type_;
  std::vector<std::string> data_;

  DISALLOW_COPY_AND_ASSIGN(MockHttpResponse);
};

MockHttpResponse::MockHttpResponse()
    : status_code_success_(true),
      status_code_(200),
      content_length_success_(true),
      has_content_length_(false),
      content_length_(0),
      content_type_success_(true),
      has_content_type_(false) {
  data_.push_back(std::string());
}

bool MockHttpResponse::GetStatusCode(uint16_t* status_code) {
  DCHECK(status_code);
  if (status_code && status_code_success_)
    *status_code = status_code_;
  return status_code_success_;
}

bool MockHttpResponse::GetContentLength(bool* has_content_length,
                                        size_t* content_length) {
  DCHECK(has_content_length);
  DCHECK(content_length);
  if (content_length_success_) {
    *has_content_length = has_content_length_;
    if (has_content_length_)
      *content_length = content_length_;
  }
  return content_length_success_;
}

bool MockHttpResponse::GetContentType(bool* has_content_type,
                                      base::string16* content_type) {
  DCHECK(has_content_type);
  DCHECK(content_type);
  if (content_type_success_) {
    *has_content_type = has_content_type_;
    if (has_content_type_)
      *content_type = content_type_;
  }
  return content_type_success_;
}

bool MockHttpResponse::HasData(bool* has_data) {
  DCHECK(has_data);
  if (data_.empty())
    return false;
  *has_data = !data_.front().empty();
  return true;
}

bool MockHttpResponse::ReadData(char* buffer, size_t* count) {
  DCHECK(buffer);
  DCHECK(count);
  if (data_.empty())
    return false;
  if (data_.front().empty()) {
    *count = 0;
    return true;
  }
  *count = std::min(*count, data_.front().length());
  ::memcpy(buffer, data_.front().c_str(), *count);
  data_.front().erase(0, *count);
  if (data_.front().empty())
    data_.erase(data_.begin());
  return true;
}

void MockHttpResponse::set_status_code(bool success, uint16_t status_code) {
  status_code_success_ = success;
  status_code_ = status_code;
}

void MockHttpResponse::set_content_length(bool success,
                                          bool has_content_length,
                                          size_t content_length) {
  content_length_success_ = success;
  has_content_length_ = has_content_length;
  content_length_ = content_length;
}

void MockHttpResponse::set_content_type(bool success,
                                        bool has_content_type,
                                        base::string16 content_type) {
  content_type_success_ = success;
  has_content_type_ = has_content_type;
  content_type_ = content_type;
}

void MockHttpResponse::set_data(const std::vector<std::string>& data) {
  data_ = data;
}

}  // namespace

class UploadTest : public testing::Test {
 protected:
  void SetUp() override {
    agent().expectations().host = L"example.com";
    agent().expectations().port = 80;
    agent().expectations().secure = false;
    agent().expectations().path = L"/path/to/resource";
    agent().expectations().file_name = L"file_name";
    agent().expectations().file = "file contents";
    agent().expectations().parameters[L"param"] = L"value";
  }

  MockHttpAgent& agent() { return agent_; }

  bool SendUpload(base::string16* response_body, uint16_t* response_code);

 private:
  MockHttpAgent agent_;
};

bool UploadTest::SendUpload(base::string16* response_body,
                            uint16_t* response_code) {
  return SendHttpUpload(
      &agent(), (agent().expectations().secure ? L"https://" : L"http://") +
                    agent().expectations().host + agent().expectations().path,
      agent().expectations().parameters, agent().expectations().file,
      agent().expectations().file_name, response_body, response_code);
}

TEST_F(UploadTest, PostFails) {
  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_FALSE(SendUpload(&response_body, &response_code));
}

TEST_F(UploadTest, PostSucceeds) {
  const std::string kResponse = "hello world";

  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  std::vector<std::string> data;
  data.push_back(kResponse);
  data.push_back(std::string());
  mock_response->set_data(data);
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_TRUE(SendUpload(&response_body, &response_code));
  EXPECT_EQ(200, response_code);
  EXPECT_EQ(base::UTF8ToWide(kResponse), response_body);
}

TEST_F(UploadTest, PostSucceedsSecure) {
  const std::string kResponse = "hello world";

  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  std::vector<std::string> data;
  data.push_back(kResponse);
  data.push_back(std::string());
  mock_response->set_data(data);
  agent().set_response(std::move(mock_response));
  agent().expectations().secure = true;
  agent().expectations().port = 443;

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_TRUE(SendUpload(&response_body, &response_code));
  EXPECT_EQ(200, response_code);
  EXPECT_EQ(base::UTF8ToWide(kResponse), response_body);
}

TEST_F(UploadTest, InvalidURL) {
  agent().set_expect_invocation(false);
  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_FALSE(SendHttpUpload(
      &agent(),
      L"@@::/:" + agent().expectations().host + agent().expectations().path,
      agent().expectations().parameters, agent().expectations().file,
      agent().expectations().file_name, &response_body, &response_code));
}

TEST_F(UploadTest, BadScheme) {
  agent().set_expect_invocation(false);
  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_FALSE(SendHttpUpload(
      &agent(),
      L"ftp://" + agent().expectations().host + agent().expectations().path,
      agent().expectations().parameters, agent().expectations().file,
      agent().expectations().file_name, &response_body, &response_code));
}

TEST_F(UploadTest, GetStatusFails) {
  const std::string kResponse = "hello world";

  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  mock_response->set_status_code(false, 500);
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_FALSE(SendUpload(&response_body, &response_code));
}

TEST_F(UploadTest, PostSucceedsInMultiplePackets) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  const std::string kResponse1 = "hello ";
  const std::string kResponse2 = "world";
  std::vector<std::string> data;
  data.push_back(kResponse1);
  data.push_back(kResponse2);
  data.push_back(std::string());
  mock_response->set_data(data);
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_TRUE(SendUpload(&response_body, &response_code));
  EXPECT_EQ(200, response_code);
  EXPECT_EQ(base::UTF8ToWide(kResponse1 + kResponse2), response_body);
}

TEST_F(UploadTest, PostFailsInMultiplePackets) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  const std::string kResponse1 = "hello ";
  const std::string kResponse2 = "world";
  std::vector<std::string> data;
  data.push_back(kResponse1);
  data.push_back(kResponse2);
  // By omitting an empty packet here, we tell the MockHttpResponse to fail
  // after returning the above two packets.
  mock_response->set_data(data);
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_FALSE(SendUpload(&response_body, &response_code));
}

TEST_F(UploadTest, TooMuchData) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  std::vector<std::string> data;
  data.push_back(std::string(8192, 'x'));
  data.push_back(std::string());
  mock_response->set_data(data);
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_FALSE(SendUpload(&response_body, &response_code));
}

TEST_F(UploadTest, CorrectContentLength) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  std::string kResponse = "0123456789";
  std::vector<std::string> data;
  data.push_back(kResponse);
  data.push_back(std::string());
  mock_response->set_data(data);
  mock_response->set_content_length(true, true, kResponse.length());
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_TRUE(SendUpload(&response_body, &response_code));
  EXPECT_EQ(200, response_code);
  EXPECT_EQ(base::UTF8ToWide(kResponse), response_body);
}

TEST_F(UploadTest, UnderContentLength) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  std::string kResponse = "0123456789";
  std::vector<std::string> data;
  data.push_back(kResponse);
  data.push_back(std::string());
  mock_response->set_data(data);
  mock_response->set_content_length(true, true, kResponse.length() + 1);
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_FALSE(SendUpload(&response_body, &response_code));
}

TEST_F(UploadTest, OverContentLength) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  std::string kResponse = "0123456789";
  std::vector<std::string> data;
  data.push_back(kResponse);
  data.push_back(std::string());
  mock_response->set_data(data);
  mock_response->set_content_length(true, true, kResponse.length() - 1);
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_FALSE(SendUpload(&response_body, &response_code));
}

TEST_F(UploadTest, OverContentLengthTwoPackets) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  std::string kResponse = "0123456789";
  std::vector<std::string> data;
  data.push_back(kResponse);
  data.push_back(kResponse);
  data.push_back(std::string());
  mock_response->set_data(data);
  mock_response->set_content_length(true, true, kResponse.length());
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_FALSE(SendUpload(&response_body, &response_code));
}

TEST_F(UploadTest, CorrectContentTypeAndCharset) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  std::string kResponse = "0123456789";
  std::vector<std::string> data;
  data.push_back(kResponse);
  data.push_back(std::string());
  mock_response->set_data(data);
  mock_response->set_content_type(true, true, L"text/plain; charset=utf-8");
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_TRUE(SendUpload(&response_body, &response_code));
  EXPECT_EQ(200, response_code);
  EXPECT_EQ(base::UTF8ToWide(kResponse), response_body);
}

TEST_F(UploadTest, UnsupportedCharset) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  unsigned char kResponseArray[] = {'0', '1', '2', '3', 128, 0};
  std::string kResponse = reinterpret_cast<char*>(kResponseArray);
  std::vector<std::string> data;
  data.push_back(kResponse);
  data.push_back(std::string());
  mock_response->set_data(data);
  mock_response->set_content_type(true, true,
                                  L"text/plain; charset=iso-8859-1");
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_FALSE(SendUpload(&response_body, &response_code));
}

TEST_F(UploadTest, ASCIISubsetOfLatin1) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  char kResponseArray[] = {'0', '1', '2', '3', 127, 0};
  std::string kResponse = kResponseArray;
  std::vector<std::string> data;
  data.push_back(kResponse);
  data.push_back(std::string());
  mock_response->set_data(data);
  mock_response->set_content_type(true, true,
                                  L"text/plain; charset=iso-8859-1");
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_TRUE(SendUpload(&response_body, &response_code));
  EXPECT_EQ(200, response_code);
  EXPECT_EQ(base::UTF8ToWide(kResponse), response_body);
}

TEST_F(UploadTest, UnsupportedContentType) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  std::string kResponse = "<html><body>0123456789</body></html>";
  std::vector<std::string> data;
  data.push_back(kResponse);
  data.push_back(std::string());
  mock_response->set_data(data);
  mock_response->set_content_type(true, true, L"text/html; charset=utf-8");
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_FALSE(SendUpload(&response_body, &response_code));
}

TEST_F(UploadTest, TextLabeledAsHTML) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  std::string kResponse = "0123456789";
  std::vector<std::string> data;
  data.push_back(kResponse);
  data.push_back(std::string());
  mock_response->set_data(data);
  mock_response->set_content_type(true, true, L"text/html; charset=utf-8");
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_TRUE(SendUpload(&response_body, &response_code));
  EXPECT_EQ(200, response_code);
  EXPECT_EQ(base::UTF8ToWide(kResponse), response_body);
}

TEST_F(UploadTest, CorrectContentTypeNoCharset) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  std::string kResponse = "0123456789";
  std::vector<std::string> data;
  data.push_back(kResponse);
  data.push_back(std::string());
  mock_response->set_data(data);
  mock_response->set_content_type(true, true, L"text/plain");
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_TRUE(SendUpload(&response_body, &response_code));
  EXPECT_EQ(200, response_code);
  EXPECT_EQ(base::UTF8ToWide(kResponse), response_body);
}

TEST_F(UploadTest, WideResponse) {
  std::unique_ptr<MockHttpResponse> mock_response(new MockHttpResponse);
  base::string16 kResponse = L"0123456789";
  std::vector<std::string> data;
  data.push_back(std::string(reinterpret_cast<const char*>(kResponse.data()),
                             kResponse.length() * sizeof(*kResponse.data())));
  data.push_back(std::string());
  mock_response->set_data(data);
  mock_response->set_content_type(true, true, L"text/plain; charset=utf-16");
  agent().set_response(std::move(mock_response));

  base::string16 response_body;
  uint16_t response_code = 0;
  EXPECT_TRUE(SendUpload(&response_body, &response_code));
  EXPECT_EQ(200, response_code);
  EXPECT_EQ(kResponse, response_body);
}

}  // namespace kasko
