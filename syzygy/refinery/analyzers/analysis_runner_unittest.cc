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

#include "syzygy/refinery/analyzers/analysis_runner.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/minidump/minidump.h"
#include "syzygy/refinery/analyzers/analyzer.h"
#include "syzygy/refinery/analyzers/analyzer_util.h"
#include "syzygy/refinery/process_state/process_state.h"

namespace refinery {

namespace {

using testing::_;
using testing::Return;

static const char kMockAnalyzerName[] = "MockAnalyzer";

class MockAnalyzer : public Analyzer {
 public:
  const char* name() const override { return kMockAnalyzerName; }

  MOCK_METHOD2(Analyze,
               AnalysisResult(const minidump::Minidump& minidump,
                              const ProcessAnalysis& process_analysis));
};

// Creates a mock analyzer that has an expectation it will be called once.
MockAnalyzer* CreateMockAnalyzer(Analyzer::AnalysisResult result) {
  MockAnalyzer* analyzer = new MockAnalyzer();
  EXPECT_CALL(*analyzer, Analyze(_, _)).Times(1).WillOnce(Return(result));
  return analyzer;
}

}  // namespace

TEST(AnalysisRunnerTest, BasicSuccessTest) {
  // A runner with 2 analyzers that should run and succeed.
  AnalysisRunner runner;
  for (size_t i = 0; i < 2; ++i) {
    std::unique_ptr<Analyzer> analyzer(
        CreateMockAnalyzer(Analyzer::ANALYSIS_COMPLETE));
    runner.AddAnalyzer(std::move(analyzer));
  }

  ProcessState process_state;
  SimpleProcessAnalysis analysis(&process_state);
  minidump::FileMinidump minidump;

  // Analyze.
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE, runner.Analyze(minidump, analysis));
}

TEST(AnalysisRunnerTest, BasicErrorTest) {
  // A runner with 1 analyzer that should run and return an error.
  AnalysisRunner runner;
  std::unique_ptr<Analyzer> analyzer(
      CreateMockAnalyzer(Analyzer::ANALYSIS_ERROR));
  runner.AddAnalyzer(std::move(analyzer));

  ProcessState process_state;
  SimpleProcessAnalysis analysis(&process_state);
  minidump::FileMinidump minidump;
  // Analyze.
  ASSERT_EQ(Analyzer::ANALYSIS_ERROR, runner.Analyze(minidump, analysis));
}

}  // namespace refinery
