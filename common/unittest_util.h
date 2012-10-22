// Copyright 2012 Google Inc. All Rights Reserved.
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
//
// Declares some unittest helper functions.
//
// There is no corresponding .cc file for this header; it can be freely
// included in any unittest file without incurring additional dependencies
// (other than base).

#ifndef SYZYGY_COMMON_UNITTEST_UTIL_H_
#define SYZYGY_COMMON_UNITTEST_UTIL_H_

#include "base/file_path.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "gtest/gtest.h"

namespace testing {

// Helper class to make sure that a test that plays with the log level doesn't
// change it for other tests.
class ScopedLogLevelSaver {
 public:
  ScopedLogLevelSaver() : level_(logging::GetMinLogLevel()) {
  }

  ~ScopedLogLevelSaver() {
    logging::SetMinLogLevel(level_);
  }

  int level() const { return level_; }

 private:
  int level_;
};

// An intermediate class to add helper streams to a unit-test fixture.
class ApplicationTestBase : public testing::Test {
 public:
  // @name IO Stream Accessors.
  // Call InitStreams() to route the IO streams to/from specific files;
  // otherwise, they will be routed to/from the NUL device on first use.
  // @{
  FILE* in() const { return GetOrInitFile(&in_, "r"); }
  FILE* out() const { return GetOrInitFile(&out_, "w"); }
  FILE* err() const { return GetOrInitFile(&err_, "w"); }
  // @}

  // Initialize the IO Streams to send output to specific files.
  void InitStreams(const FilePath& in_path,
                   const FilePath& out_path,
                   const FilePath& err_path) {
    ASSERT_FALSE(out_path.empty());
    ASSERT_FALSE(err_path.empty());

    in_.reset(file_util::OpenFile(in_path, "r"));
    out_.reset(file_util::OpenFile(out_path, "w"));
    err_.reset(file_util::OpenFile(err_path, "w"));

    ASSERT_TRUE(in_.get() != NULL);
    ASSERT_TRUE(out_.get() != NULL);
    ASSERT_TRUE(err_.get() != NULL);
  }

  // Manually tear down the various streams.
  void TearDownStreams() {
    ASSERT_NO_FATAL_FAILURE(TearDownStream(&in_));
    ASSERT_NO_FATAL_FAILURE(TearDownStream(&out_));
    ASSERT_NO_FATAL_FAILURE(TearDownStream(&err_));
  }

  // Creates a temporary directory, which is cleaned up after the test runs.
  void CreateTemporaryDir(FilePath* temp_dir) {
    ASSERT_TRUE(file_util::CreateNewTempDirectory(L"", temp_dir));
    temp_dirs_.push_back(*temp_dir);
  }

  // Cleans up after each test invocation.
  virtual void TearDown() OVERRIDE {
    // These need to be shut down before we can delete the temporary
    // directories.
    EXPECT_NO_FATAL_FAILURE(TearDownStreams());

    DirList::const_iterator iter;
    for (iter = temp_dirs_.begin(); iter != temp_dirs_.end(); ++iter) {
      EXPECT_TRUE(file_util::Delete(*iter, true));
    }

    Super::TearDown();
  }

 protected:
  typedef testing::Test Super;

  void TearDownStream(file_util::ScopedFILE* stream) {
    ASSERT_TRUE(stream != NULL);
    if (stream->get() == NULL)
      return;
    ASSERT_EQ(0, ::fclose(stream->get()));
    stream->reset();
  }

  // Helper to initialize a given stream to refer to the NUL device on first
  // use if it hasn't already been associated with a file.
  static FILE* GetOrInitFile(file_util::ScopedFILE* f, const char* mode) {
    DCHECK(f != NULL);
    DCHECK(mode != NULL);
    if (f->get() == NULL)
      f->reset(file_util::OpenFile(FilePath(L"NUL"), mode));
    return f->get();
  }

  // List of temporary directorys created during this test invocation.
  typedef std::vector<const FilePath> DirList;
  DirList temp_dirs_;

  // @name Replacements for the standard IO streams.
  //
  // By default they are routed to the NUL device (on first unitialized use).
  //
  // @{
  mutable file_util::ScopedFILE in_;
  mutable file_util::ScopedFILE out_;
  mutable file_util::ScopedFILE err_;
  // @}
};

}  // namespace testing

#endif  // SYZYGY_COMMON_UNITTEST_UTIL_H_
