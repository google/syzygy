// Copyright 2011 Google Inc.
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
#include "sawdust/tracer/upload.h"

#include <stdlib.h>
#include <time.h>

#include <sstream>
#include <string>

#include "base/file_path.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/scoped_temp_dir.h"
#include "base/utf_string_conversions.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "third_party/zlib/contrib/minizip/unzip.h"

namespace {

// The main purpose of this wrap is to make sure the wrapped zip file gets
// closed when a test fails.
class ScopedZipWrap {
 public:
  ScopedZipWrap() : file_(NULL) {
  }

  ~ScopedZipWrap() {
    Close();
  }

  bool Open(const FilePath& path) {
    if (file_ != NULL)
      return false;  // This would mean test code itself was buggy. Fail.
    file_ = unzOpen(WideToUTF8(path.value()).c_str());
    return file_ != NULL;
  }

  bool Close() {
    int status = UNZ_OK;
    if (file_ != NULL)
      status = unzClose(file_);
    if (status == UNZ_OK)
      file_ = NULL;
    return status == UNZ_OK;
  }

  bool CheckFileExists(const char* path) {
    if (file_ != NULL)
      return UNZ_OK == unzLocateFile(file_, path, 0);
    return false;
  }
 private:
  unzFile file_;
};

// Serves given text as content.
class ContentFromText : public IReportContentEntry {
 public:
  ContentFromText(const std::string& title, const std::string& data)
      : title_(title), content_(data) {
  }

  ~ContentFromText() { }

  std::istream& data() { return content_; }
  const char * title() const { return title_.c_str(); }

  void MarkCompleted() { content_.seekg(0); }

 private:
  std::string title_;
  std::istringstream content_;
};

// A prop to tests the abort action. Call uploader's abort when it tries to
// dismiss it
class ContentWithAbortCall : public ContentFromText {
 public:
  ContentWithAbortCall(const std::string& title, ReportUploader* uploader)
      : ContentFromText(title, "345678945678901234567678989"),
        uploader_(uploader) {
  }

  void MarkCompleted() {
    ContentFromText::MarkCompleted();
    uploader_->SignalAbort();
  }

 private:
  ReportUploader* uploader_;
};

// Random content.
class ContentFromNothing : public IReportContentEntry {
 public:
  ContentFromNothing(const char* title, unsigned int total_char_count)
      : title_(title), streambuff_(total_char_count), content_(NULL) {
    content_.rdbuf(&streambuff_);
  }

  ~ContentFromNothing() {}

  std::istream& data() { return content_; }
  const char * title() const { return title_.c_str(); }

  void MarkCompleted() { }  // Noop.

 private:
  class RandomDataBuff: public std::streambuf {
   public:
    explicit RandomDataBuff(int total_count) : counter_(total_count) {
    }

   protected:
    std::streambuf* setbuf(char_type* s, std::streamsize n) {
      return NULL;
    }

    int_type underflow() {
      if (counter_ <= 0)
        return traits_type::eof();
      *input_buffer_ = static_cast<unsigned char>(rand() % 256);

      setg(input_buffer_, input_buffer_, input_buffer_ + 1);
      --counter_;
      return traits_type::to_int_type(*input_buffer_);
    }

   private:
    int counter_;
    char input_buffer_[1];
  };

  std::string title_;
  std::istream content_;
  RandomDataBuff streambuff_;
};

// A container and an iterator over a group of test streams.
// Allows simulating failures.
class TestContentContainer : public IReportContent {
 public:
  TestContentContainer() : next_access_index_(0), error_entry_(0xFFFF) {
  }

  ~TestContentContainer() {
    for (DataContainer::const_iterator it = all_entries_.begin();
         it != all_entries_.end(); ++it) {
      delete (*it);
    }
  }

  HRESULT GetNextEntry(IReportContentEntry** entry) {
    if (next_access_index_ == error_entry_)
      return E_FAIL;

    HRESULT return_code = S_FALSE;

    IReportContentEntry* return_entry = NULL;
    if (next_access_index_ < all_entries_.size()) {
      return_code = S_OK;
      return_entry = all_entries_[next_access_index_];
      ++next_access_index_;
    }

    if (entry != NULL)
      *entry = return_entry;

    return return_code;
  }

  void Add(IReportContentEntry* new_entry) {
    all_entries_.push_back(new_entry);
  }

  void SetErrorEntry(size_t error_position) {
    error_entry_ = error_position;
  }

  void Reset() {
    next_access_index_ = 0;
    error_entry_ = 0xFFFF;
  }

 private:
  typedef std::vector<IReportContentEntry*> DataContainer;
  DataContainer all_entries_;
  size_t next_access_index_;
  size_t error_entry_;
};

// Customized version allows control over temporary path.
class TestingReportUploader : public ReportUploader {
 public:
  TestingReportUploader(const std::wstring& target, bool local)
      : ReportUploader(target, local), fail_upload_(false) {
  }

  void AssignTemporaryStoragePath(const FilePath& path) {
    temp_file_path_ = path;
  }

  void SetFailUpload(bool new_value) {
    fail_upload_ = new_value;
  }

  bool MakeTemporaryPath(FilePath* tmp_file_path) const {
    if (temp_file_path_.empty())
      return ReportUploader::MakeTemporaryPath(tmp_file_path);
    if (tmp_file_path)
      *tmp_file_path = temp_file_path_;
    return true;
  }

  HRESULT UploadArchive() {
    if (fail_upload_)
      return E_FAIL;
    return ReportUploader::UploadArchive();
  }

 private:
  FilePath temp_file_path_;
  bool fail_upload_;
};

// Base class for all upload tests.
class ReportUploadTest : public testing::Test {
 public:
  void SetUp() {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    srand(static_cast<unsigned>(time(NULL)));
  }
 protected:
  ScopedTempDir temp_dir_;
};

// Run the entire upload operation, placing output to a local temp path.
TEST_F(ReportUploadTest, CompressionToLocal) {
  FilePath file_path = temp_dir_.path().AppendASCII("CompressionToLocal.zip");

  TestingReportUploader uploader(file_path.value(), true);

  // Feed data.
  TestContentContainer data_feed;
  data_feed.Add(new ContentFromText("data.txt",
      "asjkdjkasdjka lsdjas ljklasdjkl sjklddjsk"));
  data_feed.Add(new ContentFromText("data.etl",
      "jkadjkljklasjklasdjk ,asasklklaskld asjkl"
      "jklasjkldjkljklasjklasjklasdjkljklasdklja"));
  data_feed.Add(new ContentFromText("data.01",
      "78912iodjkljklw oqp[ok;wdkld0[12pdkl;lsdkl;s"));
  data_feed.Add(new ContentFromText("data.02",
      "78912iodjkljklw oqp[ok;wdkld0[12pdkl;lsdkl;s"));
  data_feed.Add(new ContentFromText("data.03",
    "78912iodjkljklw oqp[ok;wdkld0[12pdkl;lsdkl;s"));
  // We might want to have it real big, but since it is random, the compression
  // will be really poor. So better not.
  data_feed.Add(new ContentFromNothing("nothing.dat", 0xFFFF));

  ASSERT_HRESULT_SUCCEEDED(uploader.Upload(&data_feed));
  ASSERT_TRUE(file_util::PathExists(file_path));

  // Now we will check, real quick, that the zip file contains whatever it
  // should contain.
  ScopedZipWrap verified_zip;
  ASSERT_TRUE(verified_zip.Open(file_path));
  ASSERT_TRUE(verified_zip.CheckFileExists("data.txt"));
  ASSERT_TRUE(verified_zip.CheckFileExists("data.etl"));
  ASSERT_TRUE(verified_zip.CheckFileExists("data.01"));
  ASSERT_TRUE(verified_zip.CheckFileExists("data.02"));
  ASSERT_TRUE(verified_zip.CheckFileExists("data.03"));
  ASSERT_TRUE(verified_zip.CheckFileExists("nothing.dat"));
  ASSERT_TRUE(verified_zip.Close());
}

TEST_F(ReportUploadTest, FailureRecovery) {
  FilePath temp_store = temp_dir_.path().AppendASCII("FailureRecovery.temp");
  FilePath target_file = temp_dir_.path().AppendASCII("FailureRecovery.zip");

  TestContentContainer data_feed;
  data_feed.Add(new ContentFromText("data.txt",
      "asjkdjkasdjka lsdjas ljklasdjkl sjklddjsk"));
  data_feed.Add(new ContentFromText("data.etl",
      "jkadjkljklasjklasdjk ,asasklklaskld asjkl"
      "jklasjkldjkljklasjklasjklasdjkljklasdklja"));
  data_feed.Add(new ContentFromText("data.01",
      "78912iodjkljklw oqp[ok;wdkld0[12pdkl;lsdkl;s"));
  data_feed.Add(new ContentFromText("data.02",
      "78912iodjkljklw oqp[ok;wdkld0[12pdkl;lsdkl;s"));
  data_feed.Add(new ContentFromText("data.03",
    "78912iodjkljklw oqp[ok;wdkld0[12pdkl;lsdkl;s"));

  TestingReportUploader uploader(target_file.value(), false);
  uploader.AssignTemporaryStoragePath(temp_store);
  data_feed.SetErrorEntry(3);  // There will be an error.

  // We expect the routine to fail. temp_store should be removed while
  // target_file should not even be created.
  ASSERT_HRESULT_FAILED(uploader.Upload(&data_feed));
  ASSERT_FALSE(file_util::PathExists(temp_store));
  ASSERT_FALSE(file_util::PathExists(target_file));
}

TEST_F(ReportUploadTest, AbortRunRecovery) {
  FilePath temp_store = temp_dir_.path().AppendASCII("AbortRunRecovery.temp");
  FilePath target_file = temp_dir_.path().AppendASCII("AbortRunRecovery.zip");

  TestingReportUploader uploader(target_file.value(), false);
  uploader.AssignTemporaryStoragePath(temp_store);

  TestContentContainer data_feed;
  data_feed.Add(new ContentFromText("data.txt",
      "asjkdjkasdjka lsdjas ljklasdjkl sjklddjsk"));
  data_feed.Add(new ContentFromText("data.etl",
      "jkadjkljklasjklasdjk ,asasklklaskld asjkl"
      "jklasjkldjkljklasjklasjklasdjkljklasdklja"));
  data_feed.Add(new ContentFromText("data.01",
      "78912iodjkljklw oqp[ok;wdkld0[12pdkl;lsdkl;s"));
  data_feed.Add(new ContentFromText("data.02",
      "78912iodjkljklw oqp[ok;wdkld0[12pdkl;lsdkl;s"));
  // This will cause the entire process to fail with E_ABORT.
  data_feed.Add(new ContentWithAbortCall("abort.entry", &uploader));
  data_feed.Add(new ContentFromText("data.03",
      "78912iodjkljklw oqp[ok;wdkld0[12pdkl;lsdkl;s"));

  // We expect the routine to fail. temp_store should be removed while
  // target_file should not even be created.
  ASSERT_EQ(uploader.Upload(&data_feed), E_ABORT);
  ASSERT_FALSE(file_util::PathExists(temp_store));
  ASSERT_FALSE(file_util::PathExists(target_file));
}

// The test tries the retry scenario. Twice.
TEST_F(ReportUploadTest, UploadErrorState) {
  FilePath temp_store = temp_dir_.path().AppendASCII("UploadErrorState.temp");
  FilePath target_file = temp_dir_.path().AppendASCII("UploadErrorState.zip");

  TestContentContainer data_feed;
  data_feed.Add(new ContentFromText("data.txt",
      "asjkdjkasdjka lsdjas ljklasdjkl sjklddjsk"));
  data_feed.Add(new ContentFromText("data.etl",
      "jkadjkljklasjklasdjk ,asasklklaskld asjkl"
      "jklasjkldjkljklasjklasjklasdjkljklasdklja"));
  data_feed.Add(new ContentFromText("data.01",
      "78912iodjkljklw oqp[ok;wdkld0[12pdkl;lsdkl;s"));
  data_feed.Add(new ContentFromText("data.02",
      "78912iodjkljklw oqp[ok;wdkld0[12pdkl;lsdkl;s"));

  {
    // Separate block scope will help to test auto cleanup.
    TestingReportUploader uploader(target_file.value(), true);
    uploader.AssignTemporaryStoragePath(temp_store);
    uploader.SetFailUpload(true);
    // We expect the routine to fail. target_file should not even be created,
    // but temp_store should remain.
    ASSERT_HRESULT_FAILED(uploader.Upload(&data_feed));
    ASSERT_TRUE(file_util::PathExists(temp_store));
    ASSERT_FALSE(file_util::PathExists(target_file));
  }

  // Upon block exit temp file should be removed.
  ASSERT_FALSE(file_util::PathExists(temp_store));

  {
    // Separate block scope will help to test auto cleanup.
    TestingReportUploader uploader(target_file.value(), true);
    uploader.AssignTemporaryStoragePath(temp_store);
    uploader.SetFailUpload(true);
    // We expect the routine to fail. target_file should not even be created,
    // but temp_store should remain.
    ASSERT_HRESULT_FAILED(uploader.Upload(&data_feed));
    ASSERT_TRUE(file_util::PathExists(temp_store));
    ASSERT_FALSE(file_util::PathExists(target_file));

    // The upload (to local) should succeed and we ought to see the target file.
    uploader.SetFailUpload(false);
    ASSERT_HRESULT_SUCCEEDED(uploader.UploadArchive());
    ASSERT_FALSE(file_util::PathExists(temp_store));
    ASSERT_TRUE(file_util::PathExists(target_file));
  }
}

}  // namespace
