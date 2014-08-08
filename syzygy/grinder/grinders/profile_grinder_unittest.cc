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

#include "syzygy/grinder/grinders/profile_grinder.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace grinder {
namespace grinders {

namespace {

const wchar_t kProfileTraceFile[] = L"profile_traces/trace-1.bin";

class TestProfileGrinder : public ProfileGrinder {
 public:
  // Expose for testing.
  using ProfileGrinder::CodeLocation;
  using ProfileGrinder::FunctionLocation;
  using ProfileGrinder::PartData;
  using ProfileGrinder::FindOrCreatePart;

  typedef ProfileGrinder::InvocationNodeMap InvocationNodeMap;

  using ProfileGrinder::parser_;
  using ProfileGrinder::parts_;
};

class ProfileGrinderTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  ProfileGrinderTest() : cmd_line_(base::FilePath(L"profile_grinder.exe")) {
  }

  virtual void SetUp() OVERRIDE {
    Super::Test::SetUp();
    cmd_line_.AppendSwitchASCII("mode", "profile");
  }

  void InitParser(trace::parser::ParseEventHandlerImpl* handler) {
    ASSERT_TRUE(handler != NULL);

    ASSERT_TRUE(parser_.Init(handler));

    base::FilePath trace_file =
        testing::GetExeTestDataRelativePath(kProfileTraceFile);

    ASSERT_TRUE(parser_.OpenTraceFile(trace_file));
  }

  void GrindAndOutputSucceeds() {
    TestProfileGrinder grinder;
    grinder.ParseCommandLine(&cmd_line_);

    ASSERT_NO_FATAL_FAILURE(InitParser(&grinder));
    grinder.SetParser(&parser_);
    ASSERT_TRUE(parser_.Consume());

    EXPECT_TRUE(grinder.Grind());

    testing::ScopedTempFile output_path;
    base::ScopedFILE output_file(base::OpenFile(output_path.path(), "wb"));
    ASSERT_TRUE(output_file.get() != NULL);

    EXPECT_TRUE(grinder.OutputData(output_file.get()));
    output_file.reset();

    int64 cache_grind_file_size = 0;
    ASSERT_TRUE(base::GetFileSize(output_path.path(),
                                  &cache_grind_file_size));
    EXPECT_LT(0u, cache_grind_file_size);
  }

  void IssueSetupEvents(TestProfileGrinder* grinder) {
    grinder->OnThreadName(base::Time::Now(),
                          ::GetCurrentProcessId(),
                          ::GetCurrentThreadId(),
                          "TestThread");

    grinder->OnDynamicSymbol(::GetCurrentProcessId(),
                             kFunctionSymbolId,
                             "Function");

    grinder->OnDynamicSymbol(::GetCurrentProcessId(),
                             kCallerSymbolId,
                             "Caller");
  }

  static const uint32 kFunctionSymbolId = 0x10;
  static const uint32 kCallerSymbolId = 0x33;

  void IssueSymbolInvocationEvent(TestProfileGrinder* grinder) {
    TraceBatchInvocationInfo batch = {};
    batch.invocations[0].function_symbol_id = kFunctionSymbolId;
    batch.invocations[0].caller_symbol_id = kCallerSymbolId;
    batch.invocations[0].caller_offset = 0x30;

    batch.invocations[0].num_calls = 1000;
    batch.invocations[0].flags = kFunctionIsSymbol | kCallerIsSymbol;
    batch.invocations[0].cycles_min = 10;
    batch.invocations[0].cycles_max = 1000;
    batch.invocations[0].cycles_sum = 1000 * 100;

    grinder->OnInvocationBatch(base::Time::Now(),
                               ::GetCurrentProcessId(),
                               ::GetCurrentThreadId(),
                               1,
                               &batch);
  }

  CommandLine cmd_line_;
  trace::parser::Parser parser_;
};

}  // namespace

TEST_F(ProfileGrinderTest, CodeLocation) {
  typedef TestProfileGrinder::CodeLocation CodeLocation;

  CodeLocation loc1;
  EXPECT_FALSE(loc1.is_symbol());
  EXPECT_EQ(NULL, loc1.module());
  EXPECT_EQ(0, loc1.rva());

  EXPECT_TRUE(loc1 == CodeLocation());

  // Change location to a symbol.
  const uint32 kSymbolId = 0x1345;
  const size_t kSymbolOffset = 0x13;
  loc1.Set(::GetCurrentProcessId(), kSymbolId, kSymbolOffset);
  EXPECT_TRUE(loc1.is_symbol());
  EXPECT_EQ(::GetCurrentProcessId(), loc1.process_id());
  EXPECT_EQ(kSymbolId, loc1.symbol_id());
  EXPECT_EQ(kSymbolOffset, loc1.symbol_offset());

  EXPECT_FALSE(loc1 == CodeLocation());

  // Test copy construction.
  EXPECT_TRUE(loc1 == CodeLocation(loc1));

  CodeLocation loc2;
  // loc2 differs only in offset from loc1.
  loc2.Set(::GetCurrentProcessId(), kSymbolId, 0);
  EXPECT_TRUE(loc2 != loc1);
  EXPECT_TRUE(loc2 < loc1);

  const pe::ModuleInformation kModuleInfo;
  const RVA kRva = 0x10945;
  // Change them both to module/rva, and test for equality.
  loc1.Set(&kModuleInfo, kRva);
  loc2.Set(&kModuleInfo, kRva);

  EXPECT_TRUE(loc1 == loc2);
}

TEST_F(ProfileGrinderTest, GrindSymbolTestData) {
  // Issue a symbol invocation event against a test grinder.
  TestProfileGrinder grinder;
  IssueSetupEvents(&grinder);
  IssueSymbolInvocationEvent(&grinder);

  // Grind the data.
  ASSERT_TRUE(grinder.Grind());

  // Then retrieve and validate the data.
  ASSERT_EQ(1, grinder.parts_.size());
  TestProfileGrinder::PartData* part =
      grinder.FindOrCreatePart(::GetCurrentProcessId(),
                               ::GetCurrentThreadId());

  ASSERT_TRUE(part != NULL);
  ASSERT_EQ("TestThread", part->thread_name_);

  // We get one node for the (unknown) caller, and one for the function called.
  ASSERT_EQ(2, part->nodes_.size());

  TestProfileGrinder::InvocationNodeMap::iterator it = part->nodes_.begin();

  EXPECT_TRUE(it->first.is_symbol());
  EXPECT_EQ(::GetCurrentProcessId(), it->first.process_id());
  EXPECT_EQ(kFunctionSymbolId, it->first.symbol_id());

  ++it;
  ASSERT_TRUE(it != part->nodes_.end());

  EXPECT_TRUE(it->first.is_symbol());
  EXPECT_EQ(::GetCurrentProcessId(), it->first.process_id());
  EXPECT_EQ(kCallerSymbolId, it->first.symbol_id());
}

TEST_F(ProfileGrinderTest, ParseEmptyCommandLineSucceeds) {
  TestProfileGrinder grinder;
  EXPECT_TRUE(grinder.ParseCommandLine(&cmd_line_));
  EXPECT_FALSE(grinder.thread_parts());
}

TEST_F(ProfileGrinderTest, ParseThreadPartsSwitchOnCommandLine) {
  TestProfileGrinder grinder;
  cmd_line_.AppendSwitch("thread-parts");
  EXPECT_TRUE(grinder.ParseCommandLine(&cmd_line_));
}

TEST_F(ProfileGrinderTest, SetParserSucceeds) {
  TestProfileGrinder grinder;
  grinder.ParseCommandLine(&cmd_line_);

  ASSERT_NO_FATAL_FAILURE(InitParser(&grinder));

  grinder.SetParser(&parser_);
  EXPECT_EQ(&parser_, grinder.parser_);
}

TEST_F(ProfileGrinderTest, GrindAndOutputCacheGrindDataSucceeds) {
  ASSERT_NO_FATAL_FAILURE(GrindAndOutputSucceeds());
  // TODO(etienneb): Validate the output is a valid CacheGrind file.
}

}  // namespace grinders
}  // namespace grinder
