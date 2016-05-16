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
// This class tests that Simulator calls the functions of its respective
// SimulationEventHandler if called with the test DLL.

#include "syzygy/simulate/simulator.h"

#include "gmock/gmock.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/version/syzygy_version.h"

namespace simulate {

namespace {

using testing::_;
using testing::AtLeast;
using testing::GetExeTestDataRelativePath;
using testing::Gt;

class MockSimulationEventHandler : public SimulationEventHandler {
 public:
  MOCK_METHOD2(OnProcessStarted, void(base::Time time,
                                      size_t default_page_size));

  MOCK_METHOD2(
      OnFunctionEntry,
      void(base::Time time, const block_graph::BlockGraph::Block* block));

  MOCK_METHOD2(SerializeToJSON, bool (FILE* output, bool pretty_print));
};

class SimulatorTest : public testing::PELibUnitTest {
 public:
  typedef std::vector<base::FilePath> TraceFileList;

  void InitTraceFileList() {
    const base::FilePath trace_files_initializer[] = {
        GetExeTestDataRelativePath(testing::kCallTraceTraceFiles[0]),
        GetExeTestDataRelativePath(testing::kCallTraceTraceFiles[1]),
        GetExeTestDataRelativePath(testing::kCallTraceTraceFiles[2]),
        GetExeTestDataRelativePath(testing::kCallTraceTraceFiles[3]),
    };

    trace_files_ = TraceFileList(trace_files_initializer,
        trace_files_initializer + arraysize(trace_files_initializer));
  }

  void InitSimulator() {
    module_path_ = GetExeTestDataRelativePath(testing::kTestDllName);
    instrumented_path_ = GetExeTestDataRelativePath(
        testing::kCallTraceInstrumentedTestDllName);

    simulator_.reset(new Simulator(module_path_,
                                   instrumented_path_,
                                   trace_files_,
                                   &simulation_event_handler_));
    ASSERT_TRUE(simulator_.get() != NULL);
  }

 protected:
  base::FilePath module_path_;
  base::FilePath instrumented_path_;
  TraceFileList trace_files_;
  testing::StrictMock<MockSimulationEventHandler> simulation_event_handler_;

  std::unique_ptr<Simulator> simulator_;
};

}  // namespace

TEST_F(SimulatorTest, SuccesfulRead) {
  ASSERT_NO_FATAL_FAILURE(InitTraceFileList());
  ASSERT_NO_FATAL_FAILURE(InitSimulator());

  // SerializeToJSON shouldn't be called by Simulator.
  EXPECT_CALL(simulation_event_handler_, SerializeToJSON(_, _)).Times(0);

  // We know that since each of the test trace files contains a single process,
  // OnProcessStarted will be called exactly 4 times. Also, since they are
  // RPC-instrumented trace files we will know the value of the page size, so
  // it will be called with an argument greater than 0.
  EXPECT_CALL(simulation_event_handler_, OnProcessStarted(_, Gt(0u))).Times(4);

  // We don't have that much information about OnFunctionEntry events, but at
  // least know they should happen.
  EXPECT_CALL(simulation_event_handler_,
              OnFunctionEntry(_, _)).Times(AtLeast(1));

  ASSERT_TRUE(simulator_->ParseTraceFiles());
}

}  // namespace simulate
