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

#include "syzygy/refinery/analyzers/thread_analyzer.h"

#include <stdint.h>

#include <vector>

#include "base/strings/stringprintf.h"
#include "gtest/gtest.h"
#include "syzygy/minidump/minidump.h"
#include "syzygy/minidump/unittest_util.h"
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/analyzers/analyzer_util.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

TEST(ThreadAnalyzerTest, Basic) {
  minidump::FileMinidump minidump;
  ASSERT_TRUE(minidump.Open(testing::TestMinidumps::GetNotepad32Dump()));
  ProcessState process_state;
  SimpleProcessAnalysis analysis(&process_state);

  ThreadAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE, analyzer.Analyze(minidump, analysis));

  scoped_refptr<ProcessState::Layer<Stack>> stack_layer;
  ASSERT_TRUE(process_state.FindLayer(&stack_layer));

  ASSERT_LE(1, stack_layer->size());
}

class ThreadAnalyzerSyntheticTest : public testing::SyntheticMinidumpTest {
};

TEST_F(ThreadAnalyzerSyntheticTest, BasicTest) {
  const size_t kThreadId = 1U;
  const Address kStackAddr = 80ULL;
  const Address kStackSize = 16U;

  // Generate a synthetic minidump with thread information.
  testing::MinidumpSpecification::ThreadSpecification thread_spec(
      kThreadId, kStackAddr, kStackSize);
  testing::MinidumpSpecification::MemorySpecification memory_spec;
  thread_spec.FillStackMemorySpecification(&memory_spec);
  testing::MinidumpSpecification spec;
  ASSERT_TRUE(spec.AddMemoryRegion(memory_spec));
  ASSERT_TRUE(spec.AddThread(thread_spec));
  ASSERT_NO_FATAL_FAILURE(Serialize(spec));

  // Analyze.
  minidump::FileMinidump minidump;
  ASSERT_TRUE(minidump.Open(dump_file()));

  ProcessState process_state;
  SimpleProcessAnalysis analysis(&process_state);

  ThreadAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE, analyzer.Analyze(minidump, analysis));

  // Validate analysis.
  StackLayerPtr stack_layer;
  ASSERT_TRUE(process_state.FindLayer(&stack_layer));
  ASSERT_EQ(1, stack_layer->size());

  std::vector<StackRecordPtr> matching_records;
  stack_layer->GetRecordsAt(kStackAddr, &matching_records);
  ASSERT_EQ(1, matching_records.size());
  ASSERT_EQ(AddressRange(kStackAddr, kStackSize),
            matching_records[0]->range());
  const Stack& stack = matching_records[0]->data();

  const ThreadInformation& thread_info = stack.thread_info();
  const MINIDUMP_THREAD* thread =
      reinterpret_cast<const MINIDUMP_THREAD*>(&thread_spec.thread_data.at(0));
  ASSERT_EQ(thread->ThreadId, thread_info.thread_id());
  ASSERT_EQ(thread->SuspendCount, thread_info.suspend_count());
  ASSERT_EQ(thread->PriorityClass, thread_info.priority_class());
  ASSERT_EQ(thread->Priority, thread_info.priority());
  ASSERT_EQ(thread->Teb, thread_info.teb_address());

  const RegisterInformation& reg_info = thread_info.register_info();
  const CONTEXT* ctx =
      reinterpret_cast<const CONTEXT*>(&thread_spec.context_data.at(0));
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
