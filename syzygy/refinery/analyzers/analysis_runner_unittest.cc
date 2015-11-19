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
#include "syzygy/refinery/process_state/process_state.h"

namespace refinery {

namespace {

using testing::_;
using testing::Return;

static const char kMockAnalyzerName[] = "MockAnalyzer";

class MockAnalyzer : public Analyzer {
 public:
  const char* name() const { return kMockAnalyzerName; }

  MOCK_METHOD2(Analyze,
               AnalysisResult(const minidump::Minidump& minidump,
                              ProcessState* process_state));
};

// Creates a mock analyzer that has an expectation it will be called once.
MockAnalyzer* CreateMockAnalyzer(ProcessState* process_state,
                                 Analyzer::AnalysisResult result) {
  MockAnalyzer* analyzer = new MockAnalyzer();
  EXPECT_CALL(*analyzer, Analyze(_, process_state))
      .Times(1)
      .WillOnce(Return(result));
  return analyzer;
}

}  // namespace

TEST(AnalysisRunnerTest, BasicSuccessTest) {
  minidump::Minidump minidump;
  ProcessState process_state;

  // A runner with 2 analyzers that should run and succeed.
  AnalysisRunner runner;
  for (size_t i = 0; i < 2; ++i) {
    scoped_ptr<MockAnalyzer> analyzer(
        CreateMockAnalyzer(&process_state, Analyzer::ANALYSIS_COMPLETE));
    runner.AddAnalyzer(analyzer.Pass());
  }

  // Analyze.
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE,
            runner.Analyze(minidump, &process_state));
}

TEST(AnalysisRunnerTest, BasicErrorTest) {
  minidump::Minidump minidump;
  ProcessState process_state;

  // A runner with 1 analyzer that should run and return an error.
  AnalysisRunner runner;
  scoped_ptr<MockAnalyzer> analyzer(
      CreateMockAnalyzer(&process_state, Analyzer::ANALYSIS_ERROR));
  runner.AddAnalyzer(analyzer.Pass());

  // Analyze.
  ASSERT_EQ(Analyzer::ANALYSIS_ERROR, runner.Analyze(minidump, &process_state));
}

}  // namespace refinery
