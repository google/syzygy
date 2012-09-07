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
// Unittests for the Asan transform.

#include "syzygy/instrument/transforms/asan_transform.h"

#include <set>
#include <vector>

#include "base/scoped_native_library.h"
#include "base/scoped_temp_dir.h"
#include "base/win/pe_image.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"
#include "third_party/distorm/files/include/mnemonics.h"

namespace instrument {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockGraph;

// A derived class to expose protected members for unit-testing.
class TestAsanBasicBlockTransform : public AsanBasicBlockTransform {
 public:
  using AsanBasicBlockTransform::InstrumentBasicBlock;

  explicit TestAsanBasicBlockTransform(BlockGraph::Reference* hook)
      : AsanBasicBlockTransform(hook) {
  }
};

class AsanTransformTest : public testing::TestDllTransformTest {
 public:
  AsanTransformTest() :
      basic_block_(0, "test block", BasicBlock::BASIC_CODE_BLOCK,
                   BasicBlock::kNoOffset, kDataSize, kBlockData),
      bb_asm_(basic_block_.instructions().begin(),
              &basic_block_.instructions()) {
  }

  void InitHookRefs() {
    hook_check_access_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 4,
                                               "hook_check_access"),
    // Set up the references to the hooks needed by SyzyAsan.
    hook_check_access_ref_ = BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4,
        hook_check_access_, 0, 0);
  }

  // Some handy constants we'll use throughout the tests.
  // @{
  static const BasicBlock::Size kDataSize;
  static const uint8 kBlockData[];
  // @}

 protected:
  ScopedTempDir temp_dir_;
  AsanTransform asan_transform_;
  BlockGraph::Block* hook_check_access_;
  BlockGraph::Reference hook_check_access_ref_;
  BasicBlock basic_block_;
  block_graph::BasicBlockAssembler bb_asm_;

};

const BasicBlock::Size AsanTransformTest::kDataSize = 32;
const uint8 AsanTransformTest::kBlockData[AsanTransformTest::kDataSize] = {};

}  // namespace

TEST_F(AsanTransformTest, SetInstrumentDLLName) {
  asan_transform_.set_instrument_dll_name("foo");
  ASSERT_EQ(strcmp(asan_transform_.instrument_dll_name(), "foo"), 0);
}

TEST_F(AsanTransformTest, ApplyAsanTransform) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &asan_transform_, &block_graph_, dos_header_block_));

  // TODO(sebmarchand): Ensure that each memory access is instrumented by
  // decomposing each block of the new block-graph into basic blocks and walk
  // through their instructions. For now it's not possible due to an issue with
  // the labels in the new block-graph.
}

TEST_F(AsanTransformTest, InjectAsanHooks) {
  // Add a read access to the memory.
  bb_asm_.mov(core::eax, block_graph::Operand(core::ebx));
  // Add a write access to the memory.
  bb_asm_.mov(block_graph::Operand(core::ecx), core::edx);

  // Instrument this basic block.
  InitHookRefs();
  TestAsanBasicBlockTransform bb_transform(&hook_check_access_ref_);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(&basic_block_));

  // Ensure that the basic block is instrumented.

  // We had 2 instructions initially, and for each of them we add 3
  // instructions, so we expect to have 2 + 3 * 2 = 8 instructions.
  ASSERT_EQ(basic_block_.instructions().size(), 8);

  // Walk through the instructions to ensure that the Asan hooks have been
  // injected.
  BasicBlock::Instructions::const_iterator iter_inst =
      basic_block_.instructions().begin();

  // First we check if the first memory access is instrumented as a read
  // access.
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_PUSH);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_LEA);
  ASSERT_EQ(iter_inst->references().size(), 1);
  ASSERT_TRUE(
      iter_inst->references().begin()->second.block() == hook_check_access_);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_CALL);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_MOV);

  // Then we check if the second memory access is well instrumented as a write
  // access.
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_PUSH);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_LEA);
  ASSERT_EQ(iter_inst->references().size(), 1);
  ASSERT_TRUE(
      iter_inst->references().begin()->second.block() == hook_check_access_);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_CALL);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_MOV);

  ASSERT_TRUE(iter_inst == basic_block_.instructions().end());
}

TEST_F(AsanTransformTest, InstrumentDifferentKindOfInstructions) {
  uint32 instrumentable_instructions = 0;

  // Generate a bunch of instrumentable and non instrumentable instructions.
  bb_asm_.mov(core::eax, block_graph::Operand(core::ebx));
  instrumentable_instructions++;
  bb_asm_.mov(block_graph::Operand(core::ecx), core::edx);
  instrumentable_instructions++;

  // Non-instrumentable.
  bb_asm_.call(block_graph::Operand(core::ecx));
  bb_asm_.push(block_graph::Operand(core::eax));
  instrumentable_instructions++;

  // Non-instrumentable.
  bb_asm_.lea(core::eax, block_graph::Operand(core::ecx));

  uint32 expected_instructions_count = basic_block_.instructions().size()
      + 3 * instrumentable_instructions;
  // Instrument this basic block.
  InitHookRefs();
  TestAsanBasicBlockTransform bb_transform(&hook_check_access_ref_);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(&basic_block_));
  ASSERT_EQ(basic_block_.instructions().size(), expected_instructions_count);
}

namespace {
using base::win::PEImage;
typedef std::set<std::string> StringSet;

bool EnumImports(const PEImage &image, LPCSTR module,
                 DWORD ordinal, LPCSTR name, DWORD hint,
                 PIMAGE_THUNK_DATA iat, PVOID cookie) {
  StringSet* modules = reinterpret_cast<StringSet*>(cookie);

  if (strcmp("asan_rtl.dll", module) == 0)
    modules->insert(name);

  return true;
}

};

TEST_F(AsanTransformTest, ImportsAreRedirected) {
  pe::PERelinker relinker;

  ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

  relinker.set_input_path(::testing::GetOutputRelativePath(kDllName));
  relinker.set_output_path(temp_dir_.path().Append(kDllName));

  relinker.AppendTransform(&asan_transform_);
  ASSERT_TRUE(relinker.Init());
  ASSERT_TRUE(relinker.Relink());

  // Load the transformed module without resolving its dependencies.
  base::NativeLibrary lib =
      ::LoadLibraryEx(relinker.output_path().value().c_str(),
                      NULL,
                      DONT_RESOLVE_DLL_REFERENCES);
  ASSERT_TRUE(lib != NULL);
  // Make sure it's unloaded on failure.
  base::ScopedNativeLibrary lib_keeper(lib);

  PEImage image(lib);
  ASSERT_TRUE(image.VerifyMagic());
  StringSet imports;
  ASSERT_TRUE(image.EnumAllImports(&EnumImports, &imports));

  // This isn't strictly speaking a full test, as we only check that the new
  // imports have been added. It's however more trouble than it's worth to
  // test this fully for now.
  StringSet expected;
  expected.insert("asan_HeapCreate");
  expected.insert("asan_HeapDestroy");
  expected.insert("asan_HeapAlloc");
  expected.insert("asan_HeapReAlloc");
  expected.insert("asan_HeapFree");
  expected.insert("asan_HeapSize");
  expected.insert("asan_HeapValidate");
  expected.insert("asan_HeapCompact");
  expected.insert("asan_HeapLock");
  expected.insert("asan_HeapUnlock");
  expected.insert("asan_HeapWalk");
  expected.insert("asan_HeapSetInformation");
  expected.insert("asan_HeapQueryInformation");
  expected.insert("asan_check_access");

  EXPECT_EQ(expected, imports);
}

}  // namespace transforms
}  // namespace instrument
