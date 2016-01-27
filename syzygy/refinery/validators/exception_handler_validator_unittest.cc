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

#include "syzygy/refinery/validators/exception_handler_validator.h"

#include <string>

#include "base/logging.h"
#include "gtest/gtest.h"
#include "syzygy/minidump/minidump.h"
#include "syzygy/minidump/unittest_util.h"
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/analyzers/analyzer_util.h"
#include "syzygy/refinery/analyzers/memory_analyzer.h"
#include "syzygy/refinery/analyzers/thread_analyzer.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

namespace {

bool RunAnalysis(const minidump::Minidump& dump, ProcessState* process_state) {
  SimpleProcessAnalysis analysis(process_state);
  MemoryAnalyzer memory_analyzer;
  if (memory_analyzer.Analyze(dump, analysis) != Analyzer::ANALYSIS_COMPLETE) {
    return false;
  }
  ThreadAnalyzer thread_analyzer;
  return thread_analyzer.Analyze(dump, analysis) == Analyzer::ANALYSIS_COMPLETE;
}

testing::MinidumpSpecification::MemorySpecification CreateTibMemorySpec(
    Address tib_addr,
    Address exception_registration_record_addr) {
  std::string tib_buffer;
  tib_buffer.resize(sizeof(NT_TIB));
  NT_TIB* tib = reinterpret_cast<NT_TIB*>(&tib_buffer.at(0));
  tib->ExceptionList = reinterpret_cast<EXCEPTION_REGISTRATION_RECORD*>(
      exception_registration_record_addr);
  return testing::MinidumpSpecification::MemorySpecification(tib_addr,
                                                             tib_buffer);
}

void SetExceptionRegistrationRecordNext(void* buffer, Address next_addr) {
  EXCEPTION_REGISTRATION_RECORD* record =
      reinterpret_cast<EXCEPTION_REGISTRATION_RECORD*>(buffer);
  record->Next = reinterpret_cast<EXCEPTION_REGISTRATION_RECORD*>(next_addr);
}

}  // namespace

TEST(ExceptionHandlerValidatorTest, AnalyzeMinidump) {
  // Process the minidump for memory and thread data.
  ProcessState process_state;

  minidump::FileMinidump minidump;
  ASSERT_TRUE(minidump.Open(testing::TestMinidumps::GetNotepad32Dump()));
  ASSERT_TRUE(RunAnalysis(minidump, &process_state));

  // Run the validator.
  ValidationReport report;
  ExceptionHandlerValidator validator;
  ASSERT_EQ(Validator::VALIDATION_COMPLETE,
            validator.Validate(&process_state, &report));
  ASSERT_EQ(0, report.error_size());
}

namespace {
const size_t kThreadId = 1U;
const Address kStackAddr = 80ULL;
const Address kStackSize = 2 * sizeof(EXCEPTION_REGISTRATION_RECORD);
const Address kTebAddress = 8000ULL;
}  // namespace

class ExceptionHandlerValidatorSyntheticTest
    : public testing::SyntheticMinidumpTest {
 protected:
  void PerformTest(const std::string& stack_buffer,
                   bool include_teb,
                   Address exception_registration_record_addr,
                   Validator::ValidationResult expected_validation_result,
                   bool is_violation_expected,
                   ViolationType expected_violation) {
    // Generate a synthetic minidump with a thread, as well as memory for its
    // stack and teb.
    testing::MinidumpSpecification::ThreadSpecification thread_spec(
        kThreadId, kStackAddr, kStackSize);
    thread_spec.SetTebAddress(kTebAddress);

    testing::MinidumpSpecification::MemorySpecification stack_memory_spec(
        kStackAddr, stack_buffer);
    testing::MinidumpSpecification spec;
    ASSERT_TRUE(spec.AddMemoryRegion(stack_memory_spec));

    if (include_teb) {
      testing::MinidumpSpecification::MemorySpecification teb_memory_spec =
          CreateTibMemorySpec(kTebAddress, exception_registration_record_addr);
      ASSERT_TRUE(spec.AddMemoryRegion(teb_memory_spec));
    }

    ASSERT_TRUE(spec.AddThread(thread_spec));
    ASSERT_NO_FATAL_FAILURE(Serialize(spec));

    // Perform analysis and validation, then inspect the report.
    ASSERT_NO_FATAL_FAILURE(Analyze());
    ASSERT_EQ(expected_validation_result, Validate());
    if (expected_validation_result != Validator::VALIDATION_COMPLETE) {
      return;
    }

    ASSERT_EQ(is_violation_expected ? 1 : 0, report_.error_size());
    if (is_violation_expected)
      ASSERT_EQ(expected_violation, report_.error(0).type());
  }

  void Analyze() {
    minidump::FileMinidump minidump;
    ASSERT_TRUE(minidump.Open(dump_file()));
    ASSERT_TRUE(RunAnalysis(minidump, &process_state_));
  }

  Validator::ValidationResult Validate() {
    ExceptionHandlerValidator validator;
    return validator.Validate(&process_state_, &report_);
  }

  ProcessState process_state_;
  ValidationReport report_;
};

TEST_F(ExceptionHandlerValidatorSyntheticTest, TebNotInDumpTest) {
  std::string stack_buffer;
  stack_buffer.resize(kStackSize);
  Address unused_addr = 0ULL;
  ASSERT_NO_FATAL_FAILURE(PerformTest(stack_buffer, false /* No Teb */,
                                      unused_addr, Validator::VALIDATION_ERROR,
                                      false, VIOLATION_UNKNOWN));
}

TEST_F(ExceptionHandlerValidatorSyntheticTest,
       NoExceptionRegistrationRecordTest) {
  std::string stack_buffer;
  stack_buffer.resize(kStackSize);
  Address no_exception_registration_record_addr = static_cast<Address>(-1);
  ASSERT_NO_FATAL_FAILURE(
      PerformTest(stack_buffer, true, no_exception_registration_record_addr,
                  Validator::VALIDATION_COMPLETE, true,
                  VIOLATION_NO_EXCEPTION_REGISTRATION_RECORD));
}

TEST_F(ExceptionHandlerValidatorSyntheticTest,
       ExceptionRegistrationRecordNotInStackTest) {
  std::string stack_buffer;
  stack_buffer.resize(kStackSize);
  Address exception_registration_record_addr = kStackAddr + kStackSize;
  ASSERT_NO_FATAL_FAILURE(
      PerformTest(stack_buffer, true, exception_registration_record_addr,
                  Validator::VALIDATION_COMPLETE, true,
                  VIOLATION_EXCEPTION_REGISTRATION_RECORD_NOT_IN_STACK));
}

TEST_F(ExceptionHandlerValidatorSyntheticTest,
       ExceptionRegistrationRecordAddressIncreaseTest) {
  std::string stack_buffer;
  stack_buffer.resize(kStackSize);
  size_t record_size = sizeof(EXCEPTION_REGISTRATION_RECORD);
  SetExceptionRegistrationRecordNext(&stack_buffer.at(0),
                                     static_cast<Address>(-1));
  SetExceptionRegistrationRecordNext(&stack_buffer.at(record_size), kStackAddr);

  Address exception_registration_record_addr = kStackAddr + record_size;
  ASSERT_NO_FATAL_FAILURE(
      PerformTest(stack_buffer, true, exception_registration_record_addr,
                  Validator::VALIDATION_COMPLETE, true,
                  VIOLATION_EXCEPTION_CHAIN_ADDRESS_DECREASE));
}

TEST_F(ExceptionHandlerValidatorSyntheticTest, BasicTest) {
  std::string stack_buffer;
  stack_buffer.resize(kStackSize);
  size_t record_size = sizeof(EXCEPTION_REGISTRATION_RECORD);
  SetExceptionRegistrationRecordNext(&stack_buffer.at(0),
                                     kStackAddr + record_size);
  SetExceptionRegistrationRecordNext(&stack_buffer.at(record_size),
                                     static_cast<Address>(-1));

  Address exception_registration_record_addr = kStackAddr;
  ASSERT_NO_FATAL_FAILURE(
      PerformTest(stack_buffer, true, exception_registration_record_addr,
                  Validator::VALIDATION_COMPLETE, false, VIOLATION_UNKNOWN));
}

}  // namespace refinery
