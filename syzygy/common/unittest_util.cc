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

#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/core/unittest_util.h"

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

  // Pass FATAL log messages, like those coming from DCHECKs to default handler
  // to crash the program.
  if (severity == logging::LOG_FATAL)
    return false;

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

ScopedEnvironmentVariable::ScopedEnvironmentVariable() {
}

ScopedEnvironmentVariable::ScopedEnvironmentVariable(base::StringPiece name,
                                                     base::StringPiece value) {
  CHECK(Set(name, value));
}

ScopedEnvironmentVariable::~ScopedEnvironmentVariable() {
  if (should_restore_) {
    CHECK(env_->SetVar(name_.c_str(), restore_value_));
  } else {
    CHECK(env_->UnSetVar(name_.c_str()));
  }
}

bool ScopedEnvironmentVariable::Set(base::StringPiece name,
                                    base::StringPiece value) {
  DCHECK(!name.empty());
  if (env_)
    return false;  // Setting more than once is disallowed.

  name.CopyToString(&name_);
  env_.reset(base::Environment::Create());
  CHECK(env_);

  // Get restoration info.
  should_restore_ = true;
  if (!env_->GetVar(name_.c_str(), &restore_value_))
    should_restore_ = false;  // Variable does not exist.

  // Set the variable.
  CHECK(env_->SetVar(name_.c_str(), value.as_string()));

  return true;
}

namespace {

// Symbol path.
const wchar_t kLocalSymbolDir[] = L"symbols";
const char kNtSymbolPathPrefix[] = "SRV*";
const char kNtSymbolPathSuffixMicrosoft[] =
    "*http://msdl.microsoft.com/download/symbols";
const char kNtSymbolPathSuffixGoogle[] =
    "*https://chromium-browser-symsrv.commondatastorage.googleapis.com";

bool GetPathValueNarrow(const base::FilePath& path, std::string* value) {
  const std::wstring value_wide = path.value();
  return base::WideToUTF8(value_wide.c_str(), value_wide.length(), value);
}

bool GetNtSymbolPathValue(std::string* nt_symbol_path) {
  DCHECK(nt_symbol_path);

  base::FilePath output_path =
      testing::GetOutputRelativePath(L"").NormalizePathSeparators();

  // Build the local symbol directory path and ensure it exists.
  base::FilePath local_symbol_path = output_path.Append(kLocalSymbolDir);
  if (!base::CreateDirectory(local_symbol_path))
    return false;

  // Build the full symbol path.
  std::string output_path_str;
  if (!GetPathValueNarrow(output_path, &output_path_str))
    return false;

  std::string local_symbol_path_microsoft;
  if (!GetPathValueNarrow(local_symbol_path.Append(L"microsoft"),
                          &local_symbol_path_microsoft)) {
    return false;
  }
  std::string local_symbol_path_google;
  if (!GetPathValueNarrow(local_symbol_path.Append(L"google"),
                          &local_symbol_path_google)) {
    return false;
  }

  base::SStringPrintf(
      nt_symbol_path, "%s;%s%s%s;%s%s%s", output_path_str.c_str(),
      kNtSymbolPathPrefix, local_symbol_path_google.c_str(),
      kNtSymbolPathSuffixGoogle, kNtSymbolPathPrefix,
      local_symbol_path_microsoft.c_str(), kNtSymbolPathSuffixMicrosoft);

  return true;
}

}  // namespace

bool ScopedSymbolPath::Setup() {
  // Override NT symbol path.
  std::string nt_symbol_path;
  if (!GetNtSymbolPathValue(&nt_symbol_path))
    return false;

  if (!nt_symbol_path_.Set(testing::kNtSymbolPathEnvVar, nt_symbol_path))
    return false;

  return true;
}

}  // namespace testing
