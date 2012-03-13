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

#include "syzygy/simulate/simulator.h"

#include "gmock/gmock.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace simulate {

namespace {

using playback::Playback;
using testing::_;
using testing::AtLeast;
using testing::GetExeTestDataRelativePath;

class MockSimulator : public Simulator {
 public:
  MockSimulator(const FilePath& module_path,
                const FilePath& instrumented_path,
                const TraceFileList& trace_files)
      : Simulator(module_path, instrumented_path, trace_files) {
  }

  MOCK_METHOD3(OnProcessStarted, void(base::Time time,
                                      DWORD process_id,
                                      const TraceSystemInfo* data));

  MOCK_METHOD4(OnBatchFunctionEntry, void(base::Time time,
                                          DWORD process_id,
                                          DWORD thread_id,
                                          const TraceBatchEnterData* data));

  bool SerializeToJSON(FILE* /*output*/, bool /*pretty_print*/) {
    return true;
  }
};

class SimulatorTest : public testing::PELibUnitTest {
 public:
  typedef std::vector<FilePath> TraceFileList;

  void InitTraceFileList() {
    const FilePath trace_files_initializer[] = {
        GetExeTestDataRelativePath(L"rpc_traces/trace-1.bin"),
        GetExeTestDataRelativePath(L"rpc_traces/trace-2.bin"),
        GetExeTestDataRelativePath(L"rpc_traces/trace-3.bin"),
        GetExeTestDataRelativePath(L"rpc_traces/trace-4.bin")
    };

    trace_files_ = Playback::TraceFileList(trace_files_initializer,
        trace_files_initializer + arraysize(trace_files_initializer));
  }

  void InitSimulator() {
    module_path_ = GetExeTestDataRelativePath(kDllName);
    instrumented_path_ = GetExeTestDataRelativePath(kRpcInstrumentedDllName);

    simulator_.reset(new MockSimulator(module_path_,
                                       instrumented_path_,
                                       trace_files_));
  }

 protected:
  FilePath module_path_;
  FilePath instrumented_path_;
  TraceFileList trace_files_;

  scoped_ptr <MockSimulator> simulator_;
};

}  // namespace


TEST_F(SimulatorTest, SuccesfulRead) {
  ASSERT_NO_FATAL_FAILURE(InitTraceFileList());
  ASSERT_NO_FATAL_FAILURE(InitSimulator());

  EXPECT_CALL(*simulator_, OnProcessStarted(_, _, _)).Times(AtLeast(1));
  EXPECT_CALL(*simulator_, OnBatchFunctionEntry(_, _, _, _)).Times(AtLeast(1));
  ASSERT_TRUE(simulator_->ParseTraceFiles());
}

}  //namespace simulate
