// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/refinery/analyzers/stack_analyzer.h"

#include <string>

#include "base/environment.h"
#include "base/logging.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/win/scoped_com_initializer.h"
#include "gtest/gtest.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/analyzers/analysis_runner.h"
#include "syzygy/refinery/analyzers/exception_analyzer.h"
#include "syzygy/refinery/analyzers/memory_analyzer.h"
#include "syzygy/refinery/analyzers/module_analyzer.h"
#include "syzygy/refinery/analyzers/thread_analyzer.h"
#include "syzygy/refinery/minidump/minidump.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

namespace {

// TODO(manzagop): factor out a testing::ScopedSetSymbolPath.
const wchar_t kLocalSymbolPathSuffix[] = L"symbols\\microsoft";
const char kNtSymbolPathEnvVar[] = "_NT_SYMBOL_PATH";
const char kNtSymbolPathPrefix[] = "SRV*";
const char kNtSymbolPathSuffix[] =
    "*http://msdl.microsoft.com/download/symbols";

}  // namespace

class StackAnalyzerTest : public testing::Test {
 protected:
  void SetUp() override {
    env_.reset(base::Environment::Create());
    if (env_.get() == NULL) {
      LOG(ERROR) << "base::Environment::Create returned NULL.";
      FAIL();
    }

    // Determine the local symbol directory and ensure it exists.
    base::FilePath local_symbol_path =
        testing::GetOutputRelativePath(kLocalSymbolPathSuffix);
    ASSERT_TRUE(base::CreateDirectory(local_symbol_path));

    // Build the full symbol path.
    const std::wstring local_symbol_path_wide = local_symbol_path.value();
    std::string local_symbol_path_narrow;
    if (!base::WideToUTF8(local_symbol_path_wide.c_str(),
                          local_symbol_path_wide.length(),
                          &local_symbol_path_narrow)) {
      FAIL();
    }
    std::string nt_symbol_path = base::StringPrintf(
        "%s%s%s", kNtSymbolPathPrefix, local_symbol_path_narrow.c_str(),
        kNtSymbolPathSuffix);

    // Set the symbol path.
    restore_symbol_path_ = true;
    if (!env_->GetVar(kNtSymbolPathEnvVar, &symbol_path_restore_value_))
      restore_symbol_path_ = false;  // Variable does not exist.

    if (!env_->SetVar(kNtSymbolPathEnvVar, nt_symbol_path)) {
      LOG(ERROR) << "Unable to override " << kNtSymbolPathEnvVar;
      FAIL();
    }
  }

  void TearDown() override {
    if (restore_symbol_path_) {
      ASSERT_TRUE(
          env_->SetVar(kNtSymbolPathEnvVar, symbol_path_restore_value_));
    }
    ASSERT_TRUE(env_->UnSetVar(kNtSymbolPathEnvVar));
  }

 private:
  scoped_ptr<base::Environment> env_;
  bool restore_symbol_path_;
  std::string symbol_path_restore_value_;
};

TEST_F(StackAnalyzerTest, AnalyzeMinidump) {
  base::win::ScopedCOMInitializer com_initializer;

  Minidump minidump;
  ASSERT_TRUE(minidump.Open(testing::TestMinidumps::GetNotepad32Dump()));

  // Analyze.
  ProcessState process_state;

  AnalysisRunner runner;

  scoped_ptr<Analyzer> analyzer(new refinery::MemoryAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());
  analyzer.reset(new refinery::ThreadAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());
  analyzer.reset(new refinery::ExceptionAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());
  analyzer.reset(new refinery::ModuleAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());
  analyzer.reset(new refinery::StackAnalyzer());
  runner.AddAnalyzer(analyzer.Pass());

  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE,
            runner.Analyze(minidump, &process_state));

  // TODO(manzagop): validate process state for stack walking information.
}

}  // namespace refinery
