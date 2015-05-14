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
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/minidump/minidump.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

TEST(ThreadAnalyzerTest, Basic) {
  Minidump minidump;
  ASSERT_TRUE(minidump.Open(testing::TestMinidumps::GetNotepad32Dump()));
  ProcessState process_state;

  ThreadAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE,
            analyzer.Analyze(minidump, &process_state));

  scoped_refptr<ProcessState::Layer<Stack>> stack_layer;
  ASSERT_TRUE(process_state.FindLayer(&stack_layer));

  ASSERT_LE(1, stack_layer->size());
}

TEST(ThreadAnalyzerTest, AnalyzeSyntheticMinidump) {
  // Generate synthetic minidump.
  testing::MinidumpSpecification spec;

  // Add memory for the stack.
  const char kStack[] = "ABCDEF";
  const Address kStackAddr = 80ULL;
  const Size kStackSize = sizeof(kStack) - 1;
  const char kPadding[] = "--";
  ASSERT_TRUE(spec.AddMemoryRegion(
      kStackAddr - (sizeof(kPadding) - 1),
      base::StringPrintf("%s%s%s", kPadding, kStack, kPadding)));

  // Add the thread.
  MINIDUMP_THREAD thread = {0};
  thread.ThreadId = 1;
  thread.SuspendCount = 2;
  thread.PriorityClass = 3;
  thread.Priority = 4;
  // TODO(manzagop): set thread.Teb once analyzer handles it.
  thread.Stack.StartOfMemoryRange = kStackAddr;
  thread.Stack.Memory.DataSize = kStackSize;
  thread.ThreadContext.DataSize = sizeof(CONTEXT);
  // Note: thread.Stack.Memory.Rva and thread.ThreadContext.Rva are set during
  // serialization.

  CONTEXT ctx = {0};
  ctx.ContextFlags = CONTEXT_SEGMENTS | CONTEXT_INTEGER | CONTEXT_CONTROL;
  ctx.SegGs = 11;
  ctx.SegFs = 12;
  ctx.SegEs = 13;
  ctx.SegDs = 14;
  ctx.Edi = 21;
  ctx.Esi = 22;
  ctx.Ebx = 23;
  ctx.Edx = 24;
  ctx.Ecx = 25;
  ctx.Eax = 26;
  ctx.Ebp = 31;
  ctx.Eip = 32;
  ctx.SegCs = 33;
  ctx.EFlags = 34;
  ctx.Esp = 35;
  ctx.SegSs = 36;

  spec.AddThread(&thread, sizeof(MINIDUMP_THREAD), &ctx, sizeof(CONTEXT));

  // Serialize the minidump.
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath minidump_path;
  ASSERT_TRUE(spec.Serialize(temp_dir, &minidump_path));

  // Analyze.
  Minidump minidump;
  ASSERT_TRUE(minidump.Open(minidump_path));

  ProcessState process_state;
  ThreadAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE,
            analyzer.Analyze(minidump, &process_state));

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
  ASSERT_EQ(1, thread_info.thread_id());
  ASSERT_EQ(2, thread_info.suspend_count());
  ASSERT_EQ(3, thread_info.priority_class());
  ASSERT_EQ(4, thread_info.priority());
  // TODO(manzagop): add thread.Teb once analyzer handles it.

  const RegisterInformation& reg_info = thread_info.register_info();
  ASSERT_EQ(11, reg_info.seg_gs());
  ASSERT_EQ(12, reg_info.seg_fs());
  ASSERT_EQ(13, reg_info.seg_es());
  ASSERT_EQ(14, reg_info.seg_ds());
  ASSERT_EQ(21, reg_info.edi());
  ASSERT_EQ(22, reg_info.esi());
  ASSERT_EQ(23, reg_info.ebx());
  ASSERT_EQ(24, reg_info.edx());
  ASSERT_EQ(25, reg_info.ecx());
  ASSERT_EQ(26, reg_info.eax());
  ASSERT_EQ(31, reg_info.ebp());
  ASSERT_EQ(32, reg_info.eip());
  ASSERT_EQ(33, reg_info.seg_cs());
  ASSERT_EQ(34, reg_info.eflags());
  ASSERT_EQ(35, reg_info.esp());
  ASSERT_EQ(36, reg_info.seg_ss());
}

}  // namespace refinery
