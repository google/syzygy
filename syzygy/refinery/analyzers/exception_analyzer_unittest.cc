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

#include "syzygy/refinery/analyzers/exception_analyzer.h"

#include <stdint.h>

#include <vector>

#include "base/files/scoped_temp_dir.h"
#include "gtest/gtest.h"
#include "syzygy/minidump/minidump.h"
#include "syzygy/minidump/unittest_util.h"
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/analyzers/analyzer_util.h"
#include "syzygy/refinery/analyzers/thread_analyzer.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

TEST(ExceptionAnalyzerTest, AnalyzeMinidump) {
  minidump::FileMinidump minidump;
  ASSERT_TRUE(minidump.Open(testing::TestMinidumps::GetNotepad32Dump()));

  ProcessState process_state;
  SimpleProcessAnalysis analysis(&process_state);

  ThreadAnalyzer thread_analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE,
            thread_analyzer.Analyze(minidump, analysis));

  ExceptionAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE, analyzer.Analyze(minidump, analysis));

  // Ensure one thread has exception data.
  StackLayerPtr stack_layer;
  ASSERT_TRUE(process_state.FindLayer(&stack_layer));
  for (StackRecordPtr stack : *stack_layer) {
    const Stack& stack_proto = stack->data();
    if (stack_proto.has_thread_info() &&
        stack_proto.thread_info().has_exception())
      return;
  }
  FAIL() << "No exception data found.";
}

class ExceptionAnalyzerSyntheticTest : public testing::SyntheticMinidumpTest {};

TEST_F(ExceptionAnalyzerSyntheticTest, NoExceptionTest) {
  // Create a minidump with no exception data.
  const char kData[] = "ABCD";
  testing::MinidumpSpecification::MemorySpecification mem_spec(80ULL, kData);
  testing::MinidumpSpecification spec;
  ASSERT_TRUE(spec.AddMemoryRegion(mem_spec));
  ASSERT_NO_FATAL_FAILURE(Serialize(spec));

  // Ensure analysis succeeds.
  minidump::FileMinidump minidump;
  ASSERT_TRUE(minidump.Open(dump_file()));

  ProcessState process_state;
  SimpleProcessAnalysis analysis(&process_state);
  ExceptionAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE, analyzer.Analyze(minidump, analysis));
}

TEST_F(ExceptionAnalyzerSyntheticTest, BasicTest) {
  using MemorySpecification =
      testing::MinidumpSpecification::MemorySpecification;
  using ThreadSpecification =
      testing::MinidumpSpecification::ThreadSpecification;
  using ExceptionSpecification =
      testing::MinidumpSpecification::ExceptionSpecification;

  // Generate a synthetic minidump with an exception (as well as thread
  // information and backing memory).
  const size_t kThreadId = 42;
  const Address kStackAddr = 80ULL;
  const Address kStackSize = 16U;

  ThreadSpecification thread_spec(kThreadId, kStackAddr, kStackSize);
  MemorySpecification memory_spec;
  testing::MinidumpSpecification spec;
  thread_spec.FillStackMemorySpecification(&memory_spec);
  ASSERT_TRUE(spec.AddMemoryRegion(memory_spec));
  ASSERT_TRUE(spec.AddThread(thread_spec));
  ExceptionSpecification exception_spec(kThreadId);
  ASSERT_TRUE(spec.AddException(exception_spec));

  ASSERT_NO_FATAL_FAILURE(Serialize(spec));

  // Analyze.
  minidump::FileMinidump minidump;
  ASSERT_TRUE(minidump.Open(dump_file()));

  ProcessState process_state;
  SimpleProcessAnalysis analysis(&process_state);
  ThreadAnalyzer thread_analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE,
            thread_analyzer.Analyze(minidump, analysis));

  ExceptionAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE, analyzer.Analyze(minidump, analysis));

  // Validate.
  StackRecordPtr stack_record;
  ASSERT_TRUE(process_state.FindStackRecord(kThreadId, &stack_record));
  const Stack& stack_proto = stack_record->data();
  ASSERT_TRUE(stack_proto.has_thread_info() &&
              stack_proto.thread_info().has_exception());
  const Exception& exception = stack_proto.thread_info().exception();
  ASSERT_EQ(kThreadId, exception.thread_id());
  ASSERT_EQ(exception_spec.exception_code, exception.exception_code());
  ASSERT_EQ(exception_spec.exception_flags, exception.exception_flags());
  ASSERT_EQ(exception_spec.exception_record, exception.exception_record());
  ASSERT_EQ(exception_spec.exception_address, exception.exception_address());
  ASSERT_EQ(exception_spec.exception_information.size(),
            exception.exception_information_size());
  ASSERT_EQ(exception_spec.exception_information[0],
            exception.exception_information(0));
  ASSERT_EQ(exception_spec.exception_information[1],
            exception.exception_information(1));

  // Validate RegisterInformation once implemented.
  const RegisterInformation& reg_info = exception.register_info();
  const CONTEXT* ctx =
      reinterpret_cast<const CONTEXT*>(&exception_spec.context_data.at(0));
  ASSERT_EQ(ctx->SegGs, reg_info.seg_gs());
  ASSERT_EQ(ctx->SegFs, reg_info.seg_fs());
  ASSERT_EQ(ctx->SegEs, reg_info.seg_es());
  ASSERT_EQ(ctx->SegDs, reg_info.seg_ds());
  ASSERT_EQ(ctx->Edi, reg_info.edi());
  ASSERT_EQ(ctx->Esi, reg_info.esi());
  ASSERT_EQ(ctx->Ebx, reg_info.ebx());
  ASSERT_EQ(ctx->Edx, reg_info.edx());
  ASSERT_EQ(ctx->Ecx, reg_info.ecx());
  ASSERT_EQ(ctx->Eax, reg_info.eax());
  ASSERT_EQ(ctx->Ebp, reg_info.ebp());
  ASSERT_EQ(ctx->Eip, reg_info.eip());
  ASSERT_EQ(ctx->SegCs, reg_info.seg_cs());
  ASSERT_EQ(ctx->EFlags, reg_info.eflags());
  ASSERT_EQ(ctx->Esp, reg_info.esp());
  ASSERT_EQ(ctx->SegSs, reg_info.seg_ss());
}

}  // namespace refinery
