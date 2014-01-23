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

#include <windows.h>

#include "base/bind.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

using testing::ScopedASanAlloc;

// A flag used in asan callback to ensure that a memory error has been detected.
bool memory_error_detected = false;

void AsanErrorCallbackWithoutComparingContext(AsanErrorInfo* error_info) {
  memory_error_detected = true;
}

// Helps to test the asan_ReadFile function.
class AsanRtlReadFileTest : public testing::TestAsanRtl {
 public:
  typedef testing::TestAsanRtl Super;

  AsanRtlReadFileTest() : temp_file_handle_(INVALID_HANDLE_VALUE) {
  }

  void SetUp() OVERRIDE {
    memory_error_detected = false;
    Super::SetUp();
    SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
    ASSERT_NO_FATAL_FAILURE(CreateTempFile());
  }

  void CreateTempFile() {
    ASSERT_EQ(kTestStringLength,
              file_util::WriteFile(temp_file_.path(),
                                   kTestString,
                                   kTestStringLength));

    temp_file_handle_.Set(::CreateFile(temp_file_.path().value().c_str(),
        GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));

    ASSERT_NE(INVALID_HANDLE_VALUE, temp_file_handle_.Get());
  }

  static const char kTestString[];
  static const size_t kTestStringLength;

 protected:
  testing::ScopedTempFile temp_file_;

  base::win::ScopedHandle temp_file_handle_;
};

const char AsanRtlReadFileTest::kTestString[] = "Test of asan_ReadFile";
const size_t AsanRtlReadFileTest::kTestStringLength =
    sizeof(AsanRtlReadFileTest::kTestString);

}  // namespace

TEST_F(AsanRtlReadFileTest, AsanReadFile) {
  // Test that the function works correctly with valid parameters. In this case
  // we don't pass an OVERLAPPED structure to the function.
  DWORD bytes_read = 0;
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  EXPECT_TRUE(ReadFileFunction(temp_file_handle_.Get(),
                               alloc.get(),
                               kTestStringLength,
                               &bytes_read,
                               NULL));
  EXPECT_EQ(kTestStringLength, bytes_read);
  EXPECT_STREQ(kTestString, alloc.get());
  EXPECT_FALSE(memory_error_detected);
}

TEST_F(AsanRtlReadFileTest, AsanReadFileWithOverlapped) {
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  // Test that the function works correctly with valid parameters. Here we pass
  // an OVERLAPPED structure to the function, which indicates that we want to do
  // the read from a given offset.
  OVERLAPPED overlapped = {};
  // Start the read from the middle of the test string.
  const size_t kOffset = kTestStringLength / 2;
  overlapped.Offset = kOffset;
  DWORD bytes_read = 0;
  EXPECT_TRUE(ReadFileFunction(temp_file_handle_.Get(),
                               alloc.get(),
                               kTestStringLength,
                               &bytes_read,
                               &overlapped));
  EXPECT_EQ(kTestStringLength - kOffset, bytes_read);
  EXPECT_STREQ(kTestString + kOffset, alloc.get());
  EXPECT_FALSE(memory_error_detected);
}

TEST_F(AsanRtlReadFileTest, AsanReadFileOverflow) {
  // Test that the function works correctly with valid parameters. In this case
  // we don't pass an OVERLAPPED structure to the function.
  DWORD bytes_read = 0;
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  EXPECT_TRUE(ReadFileFunction(temp_file_handle_.Get(),
                               alloc.get(),
                               kTestStringLength + 1,
                               &bytes_read,
                               NULL));
  EXPECT_EQ(kTestStringLength, bytes_read);
  EXPECT_EQ(0U, ::strncmp(kTestString, alloc.get(), bytes_read));
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
}

TEST_F(AsanRtlReadFileTest, AsanReadFileUAFOnOverlapped) {
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  // Test an use-after-free on the overlapped structure.
  ScopedASanAlloc<OVERLAPPED> overlapped(this, sizeof(OVERLAPPED));
  // Start the read from the middle of the test string.
  const size_t kOffset = kTestStringLength / 2;
  overlapped->Offset = kOffset;
  DWORD bytes_read = 0;
  OVERLAPPED* overlapped_ptr = overlapped.get();
  overlapped.reset(NULL);
  EXPECT_TRUE(ReadFileFunction(temp_file_handle_.Get(),
                               alloc.get(),
                               kTestStringLength,
                               &bytes_read,
                               overlapped_ptr));
  EXPECT_EQ(kTestStringLength - kOffset, bytes_read);
  EXPECT_STREQ(kTestString + kOffset, alloc.get());
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapUseAfterFree));
}

TEST_F(AsanRtlReadFileTest, AsanReadFileUseAfterFree) {
  // Test if an use-after-free on the destination buffer is correctly detected.
  DWORD bytes_read = 0;
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  char* alloc_ptr = alloc.get();
  alloc.reset(NULL);
  EXPECT_TRUE(ReadFileFunction(temp_file_handle_.Get(),
                               alloc_ptr,
                               kTestStringLength + 1,
                               &bytes_read,
                               NULL));
  EXPECT_EQ(kTestStringLength, bytes_read);
  EXPECT_STREQ(kTestString, alloc_ptr);
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapUseAfterFree));
}

namespace {

typedef ScopedASanAlloc<char>* AsanReadFileCallbackData;
AsanReadFileCallbackData readfile_callback_data = NULL;

void AsanReadFileCallback() {
  ASSERT_TRUE(readfile_callback_data != NULL);
  readfile_callback_data->reset(NULL);
}

}  // namespace

TEST_F(AsanRtlReadFileTest, AsanReadFileUAFAfterInternalCall) {
  // This test makes sure that use-after-free errors on the input buffer given
  // to the ReadFile function are correctly detected.
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  memset(alloc.get(), 0, kTestStringLength);
  char* alloc_ptr = alloc.get();
  readfile_callback_data = &alloc;

  // Set the callback that we want to use once the internal call to ReadFile
  // returns.
  SetInterceptorCallbackFunction(&AsanReadFileCallback);

  // Read from the file using the interceptor, this will call the ReadFile
  // callback once the internal call to ReadFile returns, and result in freeing
  // the buffer.
  DWORD bytes_read = 0;
  EXPECT_TRUE(ReadFileFunction(temp_file_handle_.Get(),
                               alloc.get(),
                               kTestStringLength,
                               &bytes_read,
                               NULL));

  EXPECT_EQ(kTestStringLength, bytes_read);
  EXPECT_STREQ(kTestString, alloc_ptr);
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapUseAfterFree));

  SetInterceptorCallbackFunction(NULL);
}

namespace {

// Helps to test the asan_WriteFile function.
class AsanRtlWriteFileTest : public testing::TestAsanRtl {
 public:
  typedef testing::TestAsanRtl Super;

  AsanRtlWriteFileTest()
      : temp_file_handle_(INVALID_HANDLE_VALUE) {
  }

  void SetUp() OVERRIDE {
    memory_error_detected = false;
    Super::SetUp();

    temp_file_handle_.Set(::CreateFile(temp_file_.path().value().c_str(),
                                       GENERIC_READ | GENERIC_WRITE,
                                       0,
                                       NULL,
                                       OPEN_EXISTING,
                                       FILE_ATTRIBUTE_NORMAL,
                                       NULL));
    ASSERT_NE(INVALID_HANDLE_VALUE, temp_file_handle_.Get());
    SetCallBackFunction(&AsanErrorCallbackWithoutComparingContext);
  }

  bool ReadFileContent(std::string* pipe_content, size_t kOffset) {
    EXPECT_TRUE(pipe_content != NULL);
    const size_t kMaxContentLength = 64;
    pipe_content->clear();
    pipe_content->resize(kMaxContentLength);
    DWORD bytes_read = 0;
    ::SetFilePointer(temp_file_handle_.Get(), kOffset, 0, FILE_BEGIN);
    if (::ReadFile(temp_file_handle_.Get(),
                   &(*pipe_content)[0],
                   kMaxContentLength,
                   &bytes_read,
                   NULL) == FALSE) {
      return false;
    }
    // Ensures that the buffer is big enough to store the pipe content.
    EXPECT_TRUE(bytes_read < kMaxContentLength);

    return true;
  }

  static const char kTestString[];
  static const size_t kTestStringLength;

 protected:
  testing::ScopedTempFile temp_file_;

  base::win::ScopedHandle temp_file_handle_;
};

const char AsanRtlWriteFileTest::kTestString[] = "Test of asan_WriteFile";
const size_t AsanRtlWriteFileTest::kTestStringLength =
    sizeof(AsanRtlWriteFileTest::kTestString);

}  // namespace

TEST_F(AsanRtlWriteFileTest, AsanWriteFile) {
  // Test that the function works correctly with valid parameters. In this case
  // we don't pass an OVERLAPPED structure to the function.
  DWORD bytes_written = 0;
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  EXPECT_TRUE(WriteFileFunction(temp_file_handle_.Get(),
                                kTestString,
                                kTestStringLength,
                                &bytes_written,
                                NULL));
  EXPECT_EQ(kTestStringLength, bytes_written);
  EXPECT_FALSE(memory_error_detected);
  std::string file_content;
  EXPECT_TRUE(ReadFileContent(&file_content, 0));
  EXPECT_STREQ(kTestString, file_content.c_str());
}

TEST_F(AsanRtlWriteFileTest, AsanWriteFileWithOverlapped) {
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  // Test that the function works correctly with valid parameters. Here we pass
  // an OVERLAPPED structure to the function, which indicates that we want to do
  // the write after a given offset.
  OVERLAPPED overlapped = {};
  // Start the write from the middle of the test string.
  const size_t kOffset = kTestStringLength / 2;
  overlapped.Offset = kOffset;
  DWORD bytes_written = 0;
  EXPECT_TRUE(WriteFileFunction(temp_file_handle_.Get(),
                                kTestString + kOffset,
                                kTestStringLength - kOffset,
                                &bytes_written,
                                &overlapped));
  EXPECT_EQ(kTestStringLength - kOffset, bytes_written);
  EXPECT_FALSE(memory_error_detected);
  std::string file_content;
  EXPECT_TRUE(ReadFileContent(&file_content, kOffset));
  EXPECT_STREQ(kTestString + kOffset, file_content.c_str());
}

TEST_F(AsanRtlWriteFileTest, AsanWriteFileOverflow) {
  // Test that the function works correctly with valid parameters. In this case
  // we don't pass an OVERLAPPED structure to the function.
  DWORD bytes_written = 0;
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  strcpy(alloc.get(), kTestString);
  EXPECT_TRUE(WriteFileFunction(temp_file_handle_.Get(),
                                alloc.get(),
                                kTestStringLength + 1,
                                &bytes_written,
                                NULL));
  EXPECT_EQ(kTestStringLength + 1, bytes_written);
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapBufferOverFlow));
  std::string file_content;
  EXPECT_TRUE(ReadFileContent(&file_content, 0));
  EXPECT_STREQ(kTestString, file_content.c_str());
}

TEST_F(AsanRtlWriteFileTest, AsanWriteFileUAFOnOverlapped) {
  // Test an use-after-free on the overlapped structure.
  ScopedASanAlloc<OVERLAPPED> overlapped(this, sizeof(OVERLAPPED));
  // Start the write from the middle of the test string.
  const size_t kOffset = kTestStringLength / 2;
  overlapped->Offset = kOffset;
  DWORD bytes_written = 0;
  OVERLAPPED* overlapped_ptr = overlapped.get();
  overlapped.reset(NULL);
  EXPECT_TRUE(WriteFileFunction(temp_file_handle_.Get(),
                                kTestString + kOffset,
                                kTestStringLength - kOffset,
                                &bytes_written,
                                overlapped_ptr));
  EXPECT_EQ(kTestStringLength - kOffset, bytes_written);
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapUseAfterFree));
  std::string file_content;
  EXPECT_TRUE(ReadFileContent(&file_content, kOffset));
  EXPECT_STREQ(kTestString + kOffset, file_content.c_str());
}

TEST_F(AsanRtlWriteFileTest, AsanWriteFileUseAfterFree) {
  // Test if an use-after-free on the destination buffer is correctly detected.
  DWORD bytes_written = 0;
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  strcpy(alloc.get(), kTestString);
  char* alloc_ptr = alloc.get();
  alloc.reset(NULL);
  EXPECT_TRUE(WriteFileFunction(temp_file_handle_.Get(),
                                alloc_ptr,
                                kTestStringLength,
                                &bytes_written,
                                NULL));
  EXPECT_EQ(kTestStringLength, bytes_written);
  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapUseAfterFree));
  std::string file_content;
  EXPECT_TRUE(ReadFileContent(&file_content, 0));
  EXPECT_STREQ(kTestString, file_content.c_str());
}

namespace {

typedef ScopedASanAlloc<char>* AsanWriteFileCallbackData;
AsanWriteFileCallbackData writefile_callback_data = NULL;

void AsanWriteFileCallback() {
  ASSERT_TRUE(writefile_callback_data != NULL);
  writefile_callback_data->reset(NULL);
}

}  // namespace

TEST_F(AsanRtlWriteFileTest, AsanWriteFileUAFAfterInternalCall) {
  // This test makes sure that use-after-free errors on the input buffer given
  // to the WriteFile function are correctly detected.
  ScopedASanAlloc<char> alloc(this, kTestStringLength);
  strcpy(alloc.get(), kTestString);

  writefile_callback_data = &alloc;

  // Set the callback that we want to use once the internal call to WriteFile
  // returns.
  SetInterceptorCallbackFunction(&AsanWriteFileCallback);

  // Write to the file using the interceptor, this will call the WriteFile
  // callback once the internal call to WriteFile returns, and result in freeing
  // the buffer.
  DWORD bytes_written = 0;
  EXPECT_TRUE(WriteFileFunction(temp_file_handle_.Get(),
                                alloc.get(),
                                kTestStringLength,
                                &bytes_written,
                                NULL));

  EXPECT_EQ(kTestStringLength, bytes_written);

  EXPECT_TRUE(memory_error_detected);
  EXPECT_TRUE(LogContains(HeapProxy::kHeapUseAfterFree));

  std::string file_content;
  EXPECT_TRUE(ReadFileContent(&file_content, 0));
  EXPECT_STREQ(kTestString, file_content.c_str());

  SetInterceptorCallbackFunction(NULL);
}

}  // namespace asan
}  // namespace agent
