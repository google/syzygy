// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/common/unittest_util.h"

namespace testing {

ApplicationTestBase* ApplicationTestBase::self_ = NULL;

void ApplicationTestBase::InitStreams(const base::FilePath& in_path,
                                      const base::FilePath& out_path,
                                      const base::FilePath& err_path) {
  ASSERT_FALSE(in_path.empty());
  ASSERT_FALSE(out_path.empty());
  ASSERT_FALSE(err_path.empty());

  in_.reset(base::OpenFile(in_path, "r"));
  out_.reset(base::OpenFile(out_path, "w"));
  err_.reset(base::OpenFile(err_path, "w"));

  ASSERT_TRUE(in_.get() != NULL);
  ASSERT_TRUE(out_.get() != NULL);
  ASSERT_TRUE(err_.get() != NULL);

  // Intercept logging.
  ASSERT_TRUE(self_ == NULL);
  ASSERT_TRUE(log_handler_ == NULL);
  self_ = this;
  log_handler_ = logging::GetLogMessageHandler();
  logging::SetLogMessageHandler(&HandleLogMessage);
}

void ApplicationTestBase::TearDownStreams() {
  if (self_ != NULL) {
    logging::SetLogMessageHandler(log_handler_);
    log_handler_ = NULL;
    self_ = NULL;
  }

  ASSERT_NO_FATAL_FAILURE(TearDownStream(&in_));
  ASSERT_NO_FATAL_FAILURE(TearDownStream(&out_));
  ASSERT_NO_FATAL_FAILURE(TearDownStream(&err_));
}

void ApplicationTestBase::SetUp() {
  Super::SetUp();

  // Save the log level so that we can restore it in TearDown.
  log_level_ = logging::GetMinLogLevel();

  // By default we don't log to console.
  log_to_console_ = false;
}

void ApplicationTestBase::TearDown() {
  logging::SetMinLogLevel(log_level_);

  // These need to be shut down before we can delete the temporary
  // directories.
  EXPECT_NO_FATAL_FAILURE(TearDownStreams());

  DirList::const_iterator iter;
  for (iter = temp_dirs_.begin(); iter != temp_dirs_.end(); ++iter) {
    bool success = base::DeleteFile(*iter, true);
    // VS2013 holds open handles to any PDB file that has been loaded while
    // the debugger is active. This often prevents our unittests from
    // cleaning up after themselves.
    EXPECT_TRUE(success || ::IsDebuggerPresent());
  }

  Super::TearDown();
}

bool ApplicationTestBase::HandleLogMessage(int severity, const char* file,
    int line, size_t message_start, const std::string& str) {
  DCHECK(self_ != NULL);
  if (severity < logging::GetMinLogLevel())
    return true;
  fprintf(self_->err(), "%s", str.c_str());
  fflush(self_->err());

  // If we're logging to console then repeat the message there.
  if (self_->log_to_console_) {
    fprintf(stdout, "%s", str.c_str());
    fflush(stdout);
  }

  return true;
}

void ApplicationTestBase::TearDownStream(base::ScopedFILE* stream) {
  ASSERT_TRUE(stream != NULL);
  if (stream->get() == NULL)
    return;
  ASSERT_EQ(0, ::fclose(stream->get()));
  stream->reset();
}

FILE* ApplicationTestBase::GetOrInitFile(base::ScopedFILE* f,
                                         const char* mode) {
  DCHECK(f != NULL);
  DCHECK(mode != NULL);
  if (f->get() == NULL)
    f->reset(base::OpenFile(base::FilePath(L"NUL"), mode));
  return f->get();
}

}  // namespace testing
