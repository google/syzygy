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

#include "syzygy/relink/relink_app.h"

#include "base/strings/stringprintf.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/reorder/reorderer.h"

namespace relink {

using block_graph::BlockGraph;
using common::Application;
using core::RelativeAddress;
using ::testing::ScopedLogLevelSaver;

namespace {

class TestRelinkApp : public RelinkApp {
 public:
  using RelinkApp::input_image_path_;
  using RelinkApp::input_pdb_path_;
  using RelinkApp::output_image_path_;
  using RelinkApp::output_pdb_path_;
  using RelinkApp::order_file_path_;
  using RelinkApp::seed_;
  using RelinkApp::padding_;
  using RelinkApp::code_alignment_;
  using RelinkApp::no_augment_pdb_;
  using RelinkApp::compress_pdb_;
  using RelinkApp::no_strip_strings_;
  using RelinkApp::output_metadata_;
  using RelinkApp::overwrite_;
  using RelinkApp::fuzz_;
};

typedef common::Application<TestRelinkApp> TestApp;

class RelinkAppTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  RelinkAppTest()
      : cmd_line_(base::FilePath(L"relink.exe")),
        test_impl_(test_app_.implementation()),
        seed_(1234567),
        padding_(32),
        code_alignment_(4),
        no_augment_pdb_(false),
        compress_pdb_(false),
        no_strip_strings_(false),
        output_metadata_(false),
        overwrite_(false) {
  }

  void SetUp() {
    Super::SetUp();

    // Several of the tests generate progress and (deliberate) error messages
    // that would otherwise clutter the unittest output.
    logging::SetMinLogLevel(logging::LOG_FATAL);

    // Setup the IO streams.
    CreateTemporaryDir(&temp_dir_);
    stdin_path_ = temp_dir_.Append(L"NUL");
    stdout_path_ = temp_dir_.Append(L"stdout.txt");
    stderr_path_ = temp_dir_.Append(L"stderr.txt");
    InitStreams(stdin_path_, stdout_path_, stderr_path_);

    // Initialize the (potential) input and output path values.
    abs_input_image_path_ = testing::GetExeTestDataRelativePath(
        testing::kTestDllName);
    input_image_path_ = testing::GetRelativePath(abs_input_image_path_);
    abs_input_pdb_path_ = testing::GetExeTestDataRelativePath(
        testing::kTestDllPdbName);
    input_pdb_path_ = testing::GetRelativePath(abs_input_pdb_path_);
    output_image_path_ = temp_dir_.Append(input_image_path_.BaseName());
    output_pdb_path_ = temp_dir_.Append(input_pdb_path_.BaseName());
    order_file_path_ = temp_dir_.Append(L"order.json");

    // Point the application at the test's command-line and IO streams.
    test_app_.set_command_line(&cmd_line_);
    test_app_.set_in(in());
    test_app_.set_out(out());
    test_app_.set_err(err());
  }

  void GetDllMain(const pe::ImageLayout& layout, BlockGraph::Block** dll_main) {
    ASSERT_TRUE(dll_main != NULL);
    BlockGraph::Block* dos_header_block = layout.blocks.GetBlockByAddress(
        RelativeAddress(0));
    ASSERT_TRUE(dos_header_block != NULL);
    BlockGraph::Block* nt_headers_block =
        pe::GetNtHeadersBlockFromDosHeaderBlock(dos_header_block);
    ASSERT_TRUE(nt_headers_block != NULL);
    block_graph::ConstTypedBlock<IMAGE_NT_HEADERS> nt_headers;
    ASSERT_TRUE(nt_headers.Init(0, nt_headers_block));
    BlockGraph::Reference dll_main_ref;
    ASSERT_TRUE(nt_headers_block->GetReference(
        nt_headers.OffsetOf(nt_headers->OptionalHeader.AddressOfEntryPoint),
        &dll_main_ref));
    ASSERT_EQ(0u, dll_main_ref.offset());
    ASSERT_EQ(0u, dll_main_ref.base());
    *dll_main = dll_main_ref.referenced();
  }

  // Stashes the current log-level before each test instance and restores it
  // after each test completes.
  ScopedLogLevelSaver log_level_saver;

  // @name The application under test.
  // @{
  TestApp test_app_;
  TestApp::Implementation& test_impl_;
  base::FilePath temp_dir_;
  base::FilePath stdin_path_;
  base::FilePath stdout_path_;
  base::FilePath stderr_path_;
  // @}

  // @name Command-line and parameters.
  // @{
  CommandLine cmd_line_;
  base::FilePath input_image_path_;
  base::FilePath input_pdb_path_;
  base::FilePath output_image_path_;
  base::FilePath output_pdb_path_;
  base::FilePath order_file_path_;
  uint32 seed_;
  size_t padding_;
  size_t code_alignment_;
  bool no_augment_pdb_;
  bool compress_pdb_;
  bool no_strip_strings_;
  bool output_metadata_;
  bool overwrite_;
  // @}

  // @name Expected final values of input parameters.
  // @{
  base::FilePath abs_input_image_path_;
  base::FilePath abs_input_pdb_path_;
  // @}
};

}  // namespace

TEST_F(RelinkAppTest, GetHelp) {
  cmd_line_.AppendSwitch("help");
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, EmptyCommandLineFails) {
  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseWithNeitherInputNorOrderFails) {
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseWithSeedAndOrderFails) {
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchASCII("seed", base::StringPrintf("%d", seed_));
  cmd_line_.AppendSwitchPath("order_file", order_file_path_);

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseWithEmptySeedFails) {
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitch("seed");

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseWithInvalidSeedFails) {
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchASCII("seed", "hello");

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseWithEmptyPaddingFails) {
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitch("padding");

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseWithInvalidPaddingFails) {
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchASCII("padding", "hello");

  ASSERT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, ParseMinimalCommandLineWithInputDll) {
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(RelinkAppTest, ParseMinimalCommandLineWithOrderFile) {
  // The order file doesn't actually exist, so setup should fail to infer the
  // input dll.
  cmd_line_.AppendSwitchPath("order-file", order_file_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(0, test_impl_.seed_);
  EXPECT_EQ(0, test_impl_.padding_);
  EXPECT_EQ(1, test_impl_.code_alignment_);
  EXPECT_FALSE(test_impl_.no_augment_pdb_);
  EXPECT_FALSE(test_impl_.compress_pdb_);
  EXPECT_FALSE(test_impl_.no_strip_strings_);
  EXPECT_TRUE(test_impl_.output_metadata_);
  EXPECT_FALSE(test_impl_.overwrite_);
  EXPECT_FALSE(test_impl_.fuzz_);

  EXPECT_FALSE(test_impl_.SetUp());
}

TEST_F(RelinkAppTest, ParseFullCommandLineWithOrderFile) {
  // Note that we specify the no-metadata flag, so we expect false below
  // for the output_metadata_ member. Also note that neither seed nor padding
  // are given, and should default to 0.
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchPath("order-file", order_file_path_);
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("compress-pdb");
  cmd_line_.AppendSwitch("no-strip-strings");
  cmd_line_.AppendSwitch("no-metadata");
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("fuzz");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(test_impl_.input_image_path_.empty());
  EXPECT_TRUE(test_impl_.input_pdb_path_.empty());
  EXPECT_EQ(output_image_path_, test_impl_.output_image_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_EQ(order_file_path_, test_impl_.order_file_path_);
  EXPECT_EQ(0, test_impl_.seed_);
  EXPECT_EQ(0, test_impl_.padding_);
  EXPECT_EQ(1, test_impl_.code_alignment_);
  EXPECT_TRUE(test_impl_.no_augment_pdb_);
  EXPECT_TRUE(test_impl_.compress_pdb_);
  EXPECT_TRUE(test_impl_.no_strip_strings_);
  EXPECT_FALSE(test_impl_.output_metadata_);
  EXPECT_TRUE(test_impl_.overwrite_);
  EXPECT_TRUE(test_impl_.fuzz_);

  // The order file doesn't actually exist, so setup should fail to infer the
  // input dll.
  EXPECT_FALSE(test_impl_.SetUp());
}

TEST_F(RelinkAppTest, ParseFullCommandLineWithInputSeedAndMetadata) {
  // Note that we omit the no-metadata flag, so we expect true below for the
  // output_metadata_ member.
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchASCII("seed", base::StringPrintf("%d", seed_));
  cmd_line_.AppendSwitchASCII("padding", base::StringPrintf("%d", padding_));
  cmd_line_.AppendSwitchASCII("code-alignment",
                              base::StringPrintf("%d", code_alignment_));
  cmd_line_.AppendSwitch("no-augment-pdb");
  cmd_line_.AppendSwitch("compress-pdb");
  cmd_line_.AppendSwitch("no-strip-strings");
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("fuzz");

  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(abs_input_image_path_, test_impl_.input_image_path_);
  EXPECT_EQ(abs_input_pdb_path_, test_impl_.input_pdb_path_);
  EXPECT_EQ(output_image_path_, test_impl_.output_image_path_);
  EXPECT_EQ(output_pdb_path_, test_impl_.output_pdb_path_);
  EXPECT_TRUE(test_impl_.order_file_path_.empty());
  EXPECT_EQ(seed_, test_impl_.seed_);
  EXPECT_EQ(padding_, test_impl_.padding_);
  EXPECT_EQ(code_alignment_, test_impl_.code_alignment_);
  EXPECT_TRUE(test_impl_.no_augment_pdb_);
  EXPECT_TRUE(test_impl_.compress_pdb_);
  EXPECT_TRUE(test_impl_.no_strip_strings_);
  EXPECT_TRUE(test_impl_.output_metadata_);
  EXPECT_TRUE(test_impl_.overwrite_);
  EXPECT_TRUE(test_impl_.fuzz_);

  // SetUp() has nothing else to infer so it should succeed.
  EXPECT_TRUE(test_impl_.SetUp());
}

TEST_F(RelinkAppTest, DeprecatedFlagsSucceeds) {
  cmd_line_.AppendSwitchPath("input-dll", input_image_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_image_path_);
  EXPECT_TRUE(test_impl_.ParseCommandLine(&cmd_line_));

  EXPECT_EQ(abs_input_image_path_, test_impl_.input_image_path_);
  EXPECT_EQ(output_image_path_, test_impl_.output_image_path_);
}

TEST_F(RelinkAppTest, DeprecatedFlagsConflictingInputsFail) {
  cmd_line_.AppendSwitchPath("input-dll", input_image_path_);
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_image_path_);
  EXPECT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, DeprecatedFlagsConflictingOutputsFail) {
  cmd_line_.AppendSwitchPath("input-dll", input_image_path_);
  cmd_line_.AppendSwitchPath("output-dll", output_image_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  EXPECT_FALSE(test_impl_.ParseCommandLine(&cmd_line_));
}

TEST_F(RelinkAppTest, RandomRelink) {
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchASCII("seed", base::StringPrintf("%d", seed_));
  cmd_line_.AppendSwitchASCII("padding", base::StringPrintf("%d", padding_));
  cmd_line_.AppendSwitch("overwrite");

  ASSERT_EQ(0, test_app_.Run());
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_image_path_));
}

TEST_F(RelinkAppTest, RandomRelinkBasicBlocks) {
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchASCII("seed", base::StringPrintf("%d", seed_));
  cmd_line_.AppendSwitchASCII("padding", base::StringPrintf("%d", padding_));
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("basic-blocks");
  cmd_line_.AppendSwitch("exclude-bb-padding");

  ASSERT_EQ(0, test_app_.Run());
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_image_path_));
}

TEST_F(RelinkAppTest, RandomRelinkBasicBlocksWithFuzzing) {
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchASCII("seed", base::StringPrintf("%d", seed_));
  cmd_line_.AppendSwitchASCII("padding", base::StringPrintf("%d", padding_));
  cmd_line_.AppendSwitch("overwrite");
  cmd_line_.AppendSwitch("basic-blocks");
  cmd_line_.AppendSwitch("exclude-bb-padding");
  cmd_line_.AppendSwitch("fuzz");

  ASSERT_EQ(0, test_app_.Run());
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_image_path_));
}

TEST_F(RelinkAppTest, RelinkBlockOrder) {
  pe::PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(input_image_path_));

  BlockGraph bg;
  pe::ImageLayout layout(&bg);
  pe::Decomposer decomposer(pe_file);
  ASSERT_TRUE(decomposer.Decompose(&layout));

  // Get the DLL main entry point.
  BlockGraph::Block* dll_main_block = NULL;
  ASSERT_NO_FATAL_FAILURE(GetDllMain(layout, &dll_main_block));

  // Build a block-level ordering by placing the DLL main entry point at the
  // beginning of its section.
  BlockGraph::Section* text_section = bg.FindSection(".text");
  ASSERT_TRUE(text_section != NULL);
  reorder::Reorderer::Order order;
  order.sections.resize(1);
  order.sections[0].id = text_section->id();
  order.sections[0].name = text_section->name();
  order.sections[0].characteristics = text_section->characteristics();
  order.sections[0].blocks.resize(1);
  order.sections[0].blocks[0].block = dll_main_block;

  // Serialize the order file.
  ASSERT_TRUE(order.SerializeToJSON(pe_file, order_file_path_, false));

  // Order the test DLL using the order file we just created.
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchPath("order-file", order_file_path_);
  ASSERT_EQ(0, test_app_.Run());
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_image_path_));
}

TEST_F(RelinkAppTest, RelinkTestDataBlockOrder) {
  // Try a block-level reordering using an actual order file generated by our
  // test_data dependency.

  base::FilePath test_dll_order_json =
      testing::GetExeTestDataRelativePath(L"test_dll_order.json");

  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchPath("order-file", test_dll_order_json);
  ASSERT_EQ(0, test_app_.Run());
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_image_path_));
}

TEST_F(RelinkAppTest, RelinkBasicBlockOrder) {
  pe::PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(input_image_path_));

  BlockGraph bg;
  pe::ImageLayout layout(&bg);
  pe::Decomposer decomposer(pe_file);
  ASSERT_TRUE(decomposer.Decompose(&layout));

  // Get the DLL main entry point.
  BlockGraph::Block* dll_main_block = NULL;
  ASSERT_NO_FATAL_FAILURE(GetDllMain(layout, &dll_main_block));

  // Build a block-level ordering by splitting the DLL main block into two
  // blocks, each half in a different section.
  BlockGraph::Section* text_section = bg.FindSection(".text");
  ASSERT_TRUE(text_section != NULL);
  reorder::Reorderer::Order order;
  order.sections.resize(2);
  order.sections[0].id = text_section->id();
  order.sections[0].name = text_section->name();
  order.sections[0].characteristics = text_section->characteristics();
  order.sections[0].blocks.resize(1);
  order.sections[0].blocks[0].block = dll_main_block;
  order.sections[1].id = reorder::Reorderer::Order::SectionSpec::kNewSectionId;
  order.sections[1].name = ".text2";
  order.sections[1].characteristics = text_section->characteristics();
  order.sections[1].blocks.resize(1);
  order.sections[1].blocks[0].block = dll_main_block;

  // Decompose the block. Iterate over its basic-blocks and take turns placing
  // them into each of the two above blocks.
  block_graph::BasicBlockSubGraph bbsg;
  block_graph::BasicBlockDecomposer bb_decomposer(dll_main_block, &bbsg);
  ASSERT_TRUE(bb_decomposer.Decompose());
  ASSERT_LE(2u, bbsg.basic_blocks().size());
  block_graph::BasicBlockSubGraph::BBCollection::const_iterator bb_it =
      bbsg.basic_blocks().begin();
  for (size_t i = 0; bb_it != bbsg.basic_blocks().end(); ++bb_it, i ^= 1) {
    order.sections[i].blocks[0].basic_block_offsets.push_back(
        (*bb_it)->offset());
  }

  // Serialize the order file.
  ASSERT_TRUE(order.SerializeToJSON(pe_file, order_file_path_, false));

  // Order the test DLL using the order file we just created.
  cmd_line_.AppendSwitchPath("input-image", input_image_path_);
  cmd_line_.AppendSwitchPath("input-pdb", input_pdb_path_);
  cmd_line_.AppendSwitchPath("output-image", output_image_path_);
  cmd_line_.AppendSwitchPath("output-pdb", output_pdb_path_);
  cmd_line_.AppendSwitchPath("order-file", order_file_path_);
  ASSERT_EQ(0, test_app_.Run());
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_image_path_));
}

}  // namespace relink
