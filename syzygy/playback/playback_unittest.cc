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

#include "syzygy/playback/playback.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/omap.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/parse/parse_engine.h"
#include "syzygy/trace/parse/unittest_util.h"

namespace playback {

namespace {

using testing::_;
using testing::GetSrcRelativePath;
using testing::GetExeRelativePath;
using testing::GetExeTestDataRelativePath;
using testing::MockParseEventHandler;
using testing::Return;

// A test parse engine that exposes some internals so we can simulate some
// events.
class TestParseEngine : public trace::parser::ParseEngine {
 public:
  using trace::parser::ParseEngine::AddModuleInformation;
  using trace::parser::ParseEngine::RemoveModuleInformation;
};

// A test parser that exposes the parse engine, so we can feed it simulated
// events.
class TestParser : public trace::parser::Parser {
 public:
  TestParseEngine* active_parse_engine() const {
    return reinterpret_cast<TestParseEngine*>(active_parse_engine_);
  }
};

class PlaybackTest : public testing::PELibUnitTest {
 public:
  PlaybackTest() : image_layout_(&block_graph_) {
  }

  void SetUp() {
    module_path_ =
        GetExeTestDataRelativePath(testing::kTestDllName);

    instrumented_path_ =
        GetExeTestDataRelativePath(testing::kCallTraceInstrumentedTestDllName);

    const base::FilePath kTraceFiles[] = {
        GetExeTestDataRelativePath(testing::kCallTraceTraceFiles[0]),
        GetExeTestDataRelativePath(testing::kCallTraceTraceFiles[1]),
        GetExeTestDataRelativePath(testing::kCallTraceTraceFiles[2]),
        GetExeTestDataRelativePath(testing::kCallTraceTraceFiles[3]),
    };
    trace_files_ = Playback::TraceFileList(kTraceFiles,
        kTraceFiles + arraysize(kTraceFiles));
  }

  bool Init() {
    playback_.reset(
        new Playback(module_path_, instrumented_path_, trace_files_));

    parse_event_handler_.reset(new MockParseEventHandler);
    parser_.reset(new TestParser);
    return parser_->Init(parse_event_handler_.get());
  }

  scoped_ptr<Playback> playback_;

  base::FilePath module_path_;
  base::FilePath instrumented_path_;
  Playback::TraceFileList trace_files_;

  pe::PEFile input_dll_;
  block_graph::BlockGraph block_graph_;
  pe::ImageLayout image_layout_;

  scoped_ptr<MockParseEventHandler> parse_event_handler_;
  scoped_ptr<TestParser> parser_;
};

}  // namespace

TEST_F(PlaybackTest, MismatchedDLLTest) {
  module_path_ = GetExeTestDataRelativePath(L"randomized_test_dll.dll");

  EXPECT_TRUE(Init());
  EXPECT_FALSE(playback_->Init(&input_dll_, &image_layout_, parser_.get()));
}

TEST_F(PlaybackTest, BadTraceFile) {
  const base::FilePath kTraceFile = GetSrcRelativePath(
      L"syzygy/playback/test_data/bad-trace.bin");
  trace_files_ = Playback::TraceFileList(&kTraceFile, &kTraceFile + 1);

  EXPECT_TRUE(Init());
  EXPECT_FALSE(playback_->Init(&input_dll_, &image_layout_, parser_.get()));
}

TEST_F(PlaybackTest, SuccessfulInit) {
  EXPECT_TRUE(Init());
  EXPECT_TRUE(playback_->Init(&input_dll_, &image_layout_, parser_.get()));
}

TEST_F(PlaybackTest, ConsumeCallTraceEvents) {
  EXPECT_TRUE(Init());
  EXPECT_TRUE(playback_->Init(&input_dll_, &image_layout_, parser_.get()));

#ifdef OFFICIAL_BUILD
  static const size_t kProcessAttachCount = 4;
  static const size_t kBatchFunctionEntryCount = 4;
#else
  static const size_t kProcessAttachCount = 12;
  static const size_t kBatchFunctionEntryCount = 12;
#endif

  EXPECT_CALL(*parse_event_handler_, OnProcessStarted(_, _, _)).Times(4);
  EXPECT_CALL(*parse_event_handler_, OnProcessEnded(_, _)).Times(4);
  EXPECT_CALL(*parse_event_handler_, OnFunctionEntry(_, _, _, _)).Times(0);
  EXPECT_CALL(*parse_event_handler_, OnFunctionExit(_, _, _, _)).Times(0);
  EXPECT_CALL(*parse_event_handler_, OnBatchFunctionEntry(_, _, _, _)).
                  Times(kBatchFunctionEntryCount);
  EXPECT_CALL(*parse_event_handler_, OnProcessAttach(_, _, _, _)).
                  Times(kProcessAttachCount);
  EXPECT_CALL(*parse_event_handler_, OnThreadAttach(_, _, _, _)).Times(0);
  EXPECT_CALL(*parse_event_handler_, OnThreadDetach(_, _, _, _)).Times(0);
  EXPECT_CALL(*parse_event_handler_,
              OnInvocationBatch(_, _, _, _, _)).Times(0);

  EXPECT_TRUE(parser_->Consume());
}

TEST_F(PlaybackTest, FindFunctionBlock) {
  EXPECT_TRUE(Init());
  EXPECT_TRUE(playback_->Init(&input_dll_, &image_layout_, parser_.get()));

  // Get the instrumented module's signature. We need this so we can inject
  // modules into the parse engine.
  pe::PEFile pe_file;
  trace::parser::ModuleInformation module_info;
  ASSERT_TRUE(pe_file.Init(instrumented_path_));
  pe_file.GetSignature(&module_info);

  const DWORD kPid = 0x1234;

  // Get pointers to text and data.
  const IMAGE_SECTION_HEADER* text = input_dll_.GetSectionHeader(".text");
  const IMAGE_SECTION_HEADER* data = input_dll_.GetSectionHeader(".data");
  ASSERT_TRUE(text != NULL);
  ASSERT_TRUE(data != NULL);
  FuncAddr text_addr = reinterpret_cast<FuncAddr>(
      module_info.base_address.value() + text->VirtualAddress);
  FuncAddr data_addr = reinterpret_cast<FuncAddr>(
      module_info.base_address.value() + data->VirtualAddress);

  trace::parser::ModuleInformation other_module_info;
  other_module_info.base_address.set_value(0x3F000000);
  other_module_info.module_size = 0x00010000;
  other_module_info.module_checksum = 0xF000BA55;
  other_module_info.module_time_date_stamp = 0xDEADBEEF;
  other_module_info.path = L"other_module.dll";
  FuncAddr other_text_addr = reinterpret_cast<FuncAddr>(
      other_module_info.base_address.value() + 0x1000);

  ASSERT_TRUE(parser_->active_parse_engine()->AddModuleInformation(
      kPid, module_info));

  // We should be able to find text.
  bool error = false;
  EXPECT_TRUE(playback_->FindFunctionBlock(kPid, text_addr, &error) != NULL);
  EXPECT_FALSE(error);

  // We should get an error looking up data.
  error = false;
  EXPECT_TRUE(playback_->FindFunctionBlock(kPid, data_addr, &error) == NULL);
  EXPECT_TRUE(error);

  // We should get an error looking up an address outside of the module.
  error = false;
  EXPECT_TRUE(
      playback_->FindFunctionBlock(kPid, other_text_addr, &error) == NULL);
  EXPECT_TRUE(error);

  // Now add the dummy module. Another lookup should succeed but return NULL.
  ASSERT_TRUE(parser_->active_parse_engine()->AddModuleInformation(
      kPid, other_module_info));
  error = false;
  EXPECT_TRUE(
      playback_->FindFunctionBlock(kPid, other_text_addr, &error) == NULL);
  EXPECT_FALSE(error);
}

}  // namespace playback
