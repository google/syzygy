// Copyright 2012 Google Inc.
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

#include "syzygy/trace/parse/parse_utils.h"

#include <vector>

#include "gtest/gtest.h"
#include "syzygy/common/align.h"

namespace trace {
namespace parser {

namespace {

class ParseTraceFileHeaderBlobTest : public ::testing::Test {
 public:
  virtual void SetUp() {
    // Ensure the buffer is big enough for the header but no blob.
    buffer_.resize(offsetof(TraceFileHeader, blob_data));

    // Set up the header with typical values.
    TraceFileHeader* hdr = GetHeader();
    ::memcpy(hdr->signature, TraceFileHeader::kSignatureValue,
             sizeof(hdr->signature));
    hdr->server_version.lo = TRACE_VERSION_LO;
    hdr->server_version.hi = TRACE_VERSION_HI;
    hdr->header_size = buffer_.size();
    hdr->block_size = 512;
    hdr->process_id = 4168;
    hdr->timestamp = ::GetTickCount();
    hdr->module_base_address = 0x1000000;
    hdr->module_size = 1024 * 1024;
    hdr->module_checksum = 0xABCDEFAB;
    hdr->module_time_date_stamp = 1325376000;
  }

  // Returns the header.
  TraceFileHeader* GetHeader() {
    return reinterpret_cast<TraceFileHeader*>(&buffer_[0]);
  }

  // Aligns the blob data, leaving the aligned data zero padded.
  void Align(size_t alignment) {
    size_t size = common::AlignUp(buffer_.size(), alignment);
    buffer_.resize(size);
    GetHeader()->header_size = buffer_.size();
  }

  // Appends a single item to the blob data.
  template<typename T> void Append(const T& value) {
    size_t size = buffer_.size();
    buffer_.resize(size + sizeof(T));
    ::memcpy(&buffer_[size], &value, sizeof(T));
    GetHeader()->header_size = buffer_.size();
  }

  // Appends an array of items to the blob data.
  template<typename T> void Append(const T* data, size_t length) {
    DCHECK(data != NULL);
    size_t size = buffer_.size();
    size_t bytes = sizeof(T) * length;
    buffer_.resize(size + bytes);
    ::memcpy(&buffer_[size], data, bytes);
    GetHeader()->header_size = buffer_.size();
  }

  std::vector<uint8> buffer_;
};

}  // namespace

TEST_F(ParseTraceFileHeaderBlobTest, FailsOnTruncatedHeader) {
  // Make the header too small.
  GetHeader()->header_size--;

  TraceFileHeaderBlob blob = {};
  EXPECT_FALSE(ParseTraceFileHeaderBlob(*GetHeader(), &blob));
}

TEST_F(ParseTraceFileHeaderBlobTest, FailsOnShortData) {
  // The blob stores 3 fields, the first two which are null terminated and the
  // last which is double null terminated. These are wide character nulls. Any
  // of these fields may actually be the empty string, so anything should
  // parse as long as there are 4 wide character NULLs, or 8 zero bytes.
  // Anything less than that should fail.

  TraceFileHeaderBlob blob = {};

  for (size_t i = 0; i < 8; ++i) {
    EXPECT_FALSE(ParseTraceFileHeaderBlob(*GetHeader(), &blob));
    Append<char>(0);
  }

  EXPECT_TRUE(ParseTraceFileHeaderBlob(*GetHeader(), &blob));
}

TEST_F(ParseTraceFileHeaderBlobTest, FailsOnExtraData) {
  // The last two wide characters in the blob must be NULLs. Anything beyond
  // that and we have extra malformed data.

  // We get a trailing zero for free simply from the string literal.
  const wchar_t kData[] = L"a string\0another string\0env1\0env2\0";
  Append<wchar_t>(kData, arraysize(kData));

  TraceFileHeaderBlob blob = {};
  EXPECT_TRUE(ParseTraceFileHeaderBlob(*GetHeader(), &blob));

  const wchar_t kExtraData[] = L"extra data";
  Append<wchar_t>(kExtraData, arraysize(kExtraData));
  EXPECT_FALSE(ParseTraceFileHeaderBlob(*GetHeader(), &blob));
}

TEST_F(ParseTraceFileHeaderBlobTest, SucceedsOnGoodData) {

  const wchar_t kModulePath[] = L"C:\\path\\to\\some\\module.dll";
  const wchar_t kCommandLine[] = L"module.exe --foo --bar=bar";
  // The second trailing zero comes for free.
  const wchar_t kEnvironment[] = L"KEY1=value1\0KEY2=value2\0";

  Append<wchar_t>(kModulePath, arraysize(kModulePath));
  Append<wchar_t>(kCommandLine, arraysize(kCommandLine));
  Append<wchar_t>(kEnvironment, arraysize(kEnvironment));

  TraceFileHeaderBlob blob = {};
  EXPECT_TRUE(ParseTraceFileHeaderBlob(*GetHeader(), &blob));

  EXPECT_EQ(arraysize(kModulePath) - 1, blob.module_path_length);
  EXPECT_STREQ(kModulePath, blob.module_path);

  EXPECT_EQ(arraysize(kCommandLine) - 1, blob.command_line_length);
  EXPECT_STREQ(kCommandLine, blob.command_line);

  EXPECT_EQ(arraysize(kEnvironment), blob.environment_length);
  EXPECT_EQ(0, ::memcmp(kEnvironment, blob.environment,
                        arraysize(kEnvironment)));
}

}  // namespace parser
}  // namespace trace
