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

#include <Windows.h>  // NOLINT
#include <DbgHelp.h>

#include <memory>
#include <string>
#include <vector>

#include "base/debug/alias.h"
#include "base/files/file_path.h"
#include "base/threading/platform_thread.h"
#include "base/win/scoped_com_initializer.h"
#include "gtest/gtest.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/minidump/minidump.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/analyzers/analysis_runner.h"
#include "syzygy/refinery/analyzers/analyzer_util.h"
#include "syzygy/refinery/analyzers/exception_analyzer.h"
#include "syzygy/refinery/analyzers/memory_analyzer.h"
#include "syzygy/refinery/analyzers/module_analyzer.h"
#include "syzygy/refinery/analyzers/stack_analyzer.h"
#include "syzygy/refinery/analyzers/stack_frame_analyzer.h"
#include "syzygy/refinery/analyzers/thread_analyzer.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"
#include "syzygy/refinery/symbols/dia_symbol_provider.h"

namespace refinery {

namespace {

struct SimpleUDT {
  int one;
  const char two;
};

__declspec(noinline) DWORD GetEip() {
  return reinterpret_cast<DWORD>(_ReturnAddress());
}

}  // namespace

class StackAndFrameAnalyzersTest : public testing::Test {
 protected:
  void SetUp() override {
    // Override NT symbol path.
    ASSERT_TRUE(scoped_symbol_path_.Setup());

    symbol_provider_ = new SymbolProvider();

    expected_esp_ = 0U;
    eip_lowerbound_ = 0U;
    eip_upperbound_ = 0U;

    expected_param_address_ = 0ULL;
    expected_udt_address_ = 0ULL;
    expected_udt_ptr_address_ = 0ULL;
  }

  base::FilePath minidump_path() { return scoped_minidump_.minidump_path(); }
  uint32_t expected_esp() { return expected_esp_; }
  uint32_t eip_lowerbound() { return eip_lowerbound_; }
  uint32_t eip_upperbound() { return eip_upperbound_; }
  Address expected_param_address() { return expected_param_address_; }
  Address expected_udt_address() { return expected_udt_address_; }
  Address expected_udt_ptr_address() { return expected_udt_ptr_address_; }

  bool SetupStackFrameAndGenerateMinidump(int dummy_param) {
    bool success = true;

    // Create some local variables to validate analysis.
    SimpleUDT udt_local = {42, 'a'};
    base::debug::Alias(&udt_local);
    SimpleUDT* udt_ptr_local = &udt_local;
    base::debug::Alias(&udt_ptr_local);

    // Copy esp to expected_esp_. Note: esp must not be changed prior to calling
    // GenerateMinidump.
    __asm {
      mov ebx, this
      mov [ebx].expected_esp_, esp
    }

    eip_lowerbound_ = GetEip();

    // Note: GenerateMinidump takes one parameter. This means when the frame
    // is walked, its top should equal the captured esp less the size of that
    // argument.
    expected_esp_ -= sizeof(testing::ScopedMinidump::kMinidumpWithStacks);
    success = scoped_minidump_.GenerateMinidump(
        testing::ScopedMinidump::kMinidumpWithStacks);

    eip_upperbound_ = GetEip();

    expected_param_address_ = reinterpret_cast<Address>(&dummy_param);
    expected_udt_address_ = reinterpret_cast<Address>(&udt_local);
    expected_udt_ptr_address_ = reinterpret_cast<Address>(&udt_ptr_local);

    return success;
  }

  bool AnalyzeMinidump(ProcessState* process_state) {
    minidump::FileMinidump minidump;
    if (!minidump.Open(minidump_path()))
      return false;

    AnalysisRunner runner;
    std::unique_ptr<Analyzer> analyzer(new refinery::MemoryAnalyzer());
    runner.AddAnalyzer(std::move(analyzer));
    analyzer.reset(new refinery::ThreadAnalyzer());
    runner.AddAnalyzer(std::move(analyzer));
    analyzer.reset(new refinery::ExceptionAnalyzer());
    runner.AddAnalyzer(std::move(analyzer));
    analyzer.reset(new refinery::ModuleAnalyzer());
    runner.AddAnalyzer(std::move(analyzer));
    analyzer.reset(new refinery::StackAnalyzer());
    runner.AddAnalyzer(std::move(analyzer));
    analyzer.reset(new refinery::StackFrameAnalyzer());
    runner.AddAnalyzer(std::move(analyzer));

    scoped_refptr<DiaSymbolProvider> dia_symbol_provider(
        new DiaSymbolProvider());
    SimpleProcessAnalysis analysis(process_state, dia_symbol_provider,
                                   symbol_provider_);

    return runner.Analyze(minidump, analysis) == Analyzer::ANALYSIS_COMPLETE;
  }

  void ValidateTypedBlock(ProcessState* process_state,
                          Address expected_address,
                          Size expected_size,
                          ModuleId expected_module_id,
                          const std::string& expected_variable_name,
                          const base::string16& expected_type_name) {
    TypedBlockRecordPtr typedblock_record;
    // Note: using FindSingleRecord as there should be no typed block overlap in
    // the context of this test.
    ASSERT_TRUE(
        process_state->FindSingleRecord(expected_address, &typedblock_record));

    ASSERT_EQ(expected_address, typedblock_record->range().start());
    ASSERT_EQ(expected_size, typedblock_record->range().size());

    const TypedBlock& typedblock = typedblock_record->data();
    ASSERT_EQ(expected_module_id, typedblock.module_id());

    // Validate the recovered type id corresponds to the expected name.
    ModuleLayerAccessor accessor(process_state);
    pe::PEFile::Signature signature;
    ASSERT_TRUE(accessor.GetModuleSignature(expected_module_id, &signature));

    scoped_refptr<TypeRepository> type_repository;
    ASSERT_TRUE(symbol_provider_->FindOrCreateTypeRepository(signature,
                                                             &type_repository));

    TypePtr recovered_type = type_repository->GetType(typedblock.type_id());
    ASSERT_NE(nullptr, recovered_type);
    ASSERT_EQ(expected_type_name, recovered_type->GetName());

    ASSERT_EQ(expected_variable_name, typedblock.data_name());
  }

 private:
  testing::ScopedMinidump scoped_minidump_;

  scoped_refptr<SymbolProvider> symbol_provider_;

  // For stack frame validation.
  uint32_t expected_esp_;
  uint32_t eip_lowerbound_;
  uint32_t eip_upperbound_;

  // Typed block validation.
  Address expected_param_address_;
  Address expected_udt_address_;
  Address expected_udt_ptr_address_;

  testing::ScopedSymbolPath scoped_symbol_path_;
};

// This test fails under coverage instrumentation which is probably not friendly
// to stackwalking.
#ifdef _COVERAGE_BUILD
TEST_F(StackAndFrameAnalyzersTest, DISABLED_BasicTest) {
#else
TEST_F(StackAndFrameAnalyzersTest, BasicTest) {
#endif
  base::win::ScopedCOMInitializer com_initializer;

  // Note: intentionally declared before determining expected_frame_base.
  int dummy_argument = 22;

  // Generate the minidump, then analyze it.
  // Note: the expected frame base for SetupStackFrameAndGenerateMinidump should
  // be sizeof(void*) + sizeof(int) off of the current frame's top of stack
  // immediately prior to the call (accounting for callee argument and return
  // address).
  uint32_t expected_frame_base = 0U;
  __asm {
    mov expected_frame_base, esp
  }
  expected_frame_base -= (sizeof(void*) + sizeof(int));

  ASSERT_TRUE(SetupStackFrameAndGenerateMinidump(dummy_argument));

  ProcessState process_state;
  ASSERT_TRUE(AnalyzeMinidump(&process_state));

  // Ensure the test's thread was successfully walked.
  StackRecordPtr stack;
  DWORD thread_id = ::GetCurrentThreadId();
  ASSERT_TRUE(
      process_state.FindStackRecord(static_cast<size_t>(thread_id), &stack));
  ASSERT_TRUE(stack->data().stack_walk_success());

  // Validate SetupStackFrameAndGenerateMinidump's frame.
  StackFrameRecordPtr frame_record;
  // Note: using FindSingleRecord as there should be no frame record overlap
  // in the context of this test.
  ASSERT_TRUE(process_state.FindSingleRecord(
      static_cast<Address>(expected_esp()), &frame_record));

  ASSERT_EQ(expected_esp(), frame_record->range().start());
  ASSERT_EQ(expected_frame_base - expected_esp(), frame_record->range().size());

  const StackFrame& frame = frame_record->data();
  uint32_t recovered_eip = frame.register_info().eip();
  ASSERT_LT(eip_lowerbound(), recovered_eip);
  ASSERT_GT(eip_upperbound(), recovered_eip);

  // Sanity and tightness check.
  ASSERT_GT(eip_upperbound(), eip_lowerbound());
  ASSERT_LT(eip_upperbound() - eip_lowerbound(), 100);

  // TODO(manzagop): validate frame_size_bytes. It should be sizeof(void*)
  // smaller than expected_frame_base - expected_esp(), to account for ebp
  // and since the function called into has no parameters.

  // TODO(manzagop): validate locals_base. It should be sizeof(void*) off of
  // the frame base, to account for ebp.

  // Validate typed block layer for SetupStackFrameAndGenerateMinidump.
  ModuleLayerAccessor accessor(&process_state);
  ModuleId expected_module_id = accessor.GetModuleId(recovered_eip);
  ASSERT_NE(kNoModuleId, expected_module_id);

  // - Validate some locals.
  ASSERT_NO_FATAL_FAILURE(
      ValidateTypedBlock(&process_state, expected_udt_address(),
                         sizeof(SimpleUDT), expected_module_id, "udt_local",
                         L"refinery::`anonymous-namespace'::SimpleUDT"));
  ASSERT_NO_FATAL_FAILURE(ValidateTypedBlock(
      &process_state, expected_udt_ptr_address(), sizeof(SimpleUDT*),
      expected_module_id, "udt_ptr_local",
      L"refinery::`anonymous-namespace'::SimpleUDT*"));
  // - Validate a parameter.
  ASSERT_NO_FATAL_FAILURE(
      ValidateTypedBlock(&process_state, expected_param_address(), sizeof(int),
                         expected_module_id, "dummy_param", L"int32_t"));
}

}  // namespace refinery
