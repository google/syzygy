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
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/files/scoped_temp_dir.h"
#include "base/win/pe_image.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/common/defs.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/pe/transforms/pe_add_imports_transform.h"
#include "third_party/distorm/files/include/mnemonics.h"

namespace instrument {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicCodeBlock;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockGraph;
using block_graph::Instruction;
using block_graph::RelativeAddressFilter;
using core::RelativeAddress;
typedef AsanBasicBlockTransform::MemoryAccessMode AsanMemoryAccessMode;
typedef AsanBasicBlockTransform::AsanHookMap HookMap;
typedef AsanBasicBlockTransform::AsanHookMapEntryKey HookMapEntryKey;

// A derived class to expose protected members for unit-testing.
class TestAsanBasicBlockTransform : public AsanBasicBlockTransform {
 public:
  using AsanBasicBlockTransform::InstrumentBasicBlock;

  explicit TestAsanBasicBlockTransform(AsanHookMap* hooks_check_access)
      : AsanBasicBlockTransform(hooks_check_access) {
  }
};

// A derived class to expose protected members for unit-testing.
class TestAsanTransform : public AsanTransform {
 public:
  using AsanTransform::FunctionInterceptionSet;
  using AsanTransform::InterceptFunctions;
};

class AsanTransformTest : public testing::TestDllTransformTest {
 public:
  AsanTransformTest() : basic_block_(NULL) {
    basic_block_ = subgraph_.AddBasicCodeBlock("dummy");
    bb_asm_.reset(new block_graph::BasicBlockAssembler(
        basic_block_->instructions().begin(),
        &basic_block_->instructions()));
  }

  void AddHookRef(const std::string& hook_name,
                  AsanBasicBlockTransform::MemoryAccessMode access_kind,
                  int access_size,
                  uint16_t opcode,
                  bool save_flags) {
      HookMapEntryKey map_key = {
          access_kind,
          access_size,
          opcode,
          save_flags
      };
      hooks_check_access_[map_key] =
          block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 4, hook_name);
      // Set up the references to the hooks needed by SyzyAsan.
      hooks_check_access_ref_[map_key] =
          BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4,
                                hooks_check_access_[map_key], 0, 0);
  }

  void InitHooksRefs() {
    // Initialize the read access hooks.
    for (int access_size = 1; access_size <= 8; access_size *= 2) {
      std::string name =
          base::StringPrintf("asan_check_%d_byte_read_access", access_size);
      AddHookRef(name, AsanBasicBlockTransform::kReadAccess, access_size, 0,
                 true);
      name += "_no_flags";
      AddHookRef(name, AsanBasicBlockTransform::kReadAccess, access_size, 0,
                 false);
    }
    // Initialize the write access hooks.
    for (int access_size = 1; access_size <= 8; access_size *= 2) {
      std::string name =
          base::StringPrintf("asan_check_%d_byte_write_access", access_size);
      AddHookRef(name, AsanBasicBlockTransform::kWriteAccess, access_size, 0,
                 true);
      name += "_no_flags";
      AddHookRef(name, AsanBasicBlockTransform::kWriteAccess, access_size, 0,
                 false);
    }

    const _InstructionType strings[] = { I_CMPS, I_MOVS, I_STOS };
    int strings_length = arraysize(strings);

    for (int access_size = 1; access_size <= 4; access_size *= 2) {
      for (int inst = 0; inst < strings_length; ++inst) {
        uint16_t opcode = strings[inst];
        const char* opcode_str =
            reinterpret_cast<const char*>(GET_MNEMONIC_NAME(opcode));
        std::string name =
            base::StringPrintf("asan_check_repz_%d_byte_%s_access",
                               access_size, opcode_str);
        StringToLowerASCII(&name);
        AddHookRef(name, AsanBasicBlockTransform::kRepzAccess, access_size,
                   opcode, true);
      }
    }

    // Initialize special instruction hooks.
    for (int access_size = 1; access_size <= 4; access_size *= 2) {
      for (int inst = 0; inst < strings_length; ++inst) {
        uint16_t opcode = strings[inst];
        const char* opcode_str =
            reinterpret_cast<const char*>(GET_MNEMONIC_NAME(opcode));

        // Initialize the strings without prefix access hooks.
        std::string name =
            base::StringPrintf("asan_check_%d_byte_%s_access",
                               access_size, opcode_str);
        StringToLowerASCII(&name);
        AddHookRef(name, AsanBasicBlockTransform::kInstrAccess, access_size,
                   opcode, true);

        // Initialize the strings with prefix access hooks.
         std::string repz_name =
            base::StringPrintf("asan_check_repz_%d_byte_%s_access",
                               access_size, opcode_str);
        StringToLowerASCII(&repz_name);
        AddHookRef(repz_name, AsanBasicBlockTransform::kRepzAccess, access_size,
                   opcode, true);
      }
    }
  }

  bool AddInstructionFromBuffer(const uint8* data, size_t length) {
    DCHECK(data != NULL);
    DCHECK(length < core::AssemblerImpl::kMaxInstructionLength);

    block_graph::Instruction temp;
    if (!block_graph::Instruction::FromBuffer(data, length, &temp))
      return false;

    // Append this instruction to the basic block.
    basic_block_->instructions().push_back(temp);

    return true;
  }

  // Some handy constants we'll use throughout the tests.
  // @{
  static const BasicBlock::Size kDataSize;
  static const uint8 kBlockData[];
  // @}

 protected:
  base::ScopedTempDir temp_dir_;
  TestAsanTransform asan_transform_;
  HookMap hooks_check_access_ref_;
  std::map<HookMapEntryKey, BlockGraph::Block*> hooks_check_access_;
  BasicBlockSubGraph subgraph_;
  BasicCodeBlock* basic_block_;
  scoped_ptr<block_graph::BasicBlockAssembler> bb_asm_;
};

const BasicBlock::Size AsanTransformTest::kDataSize = 32;
const uint8 AsanTransformTest::kBlockData[AsanTransformTest::kDataSize] = {};

}  // namespace

TEST_F(AsanTransformTest, SetInstrumentDLLName) {
  asan_transform_.set_instrument_dll_name("foo");
  ASSERT_EQ(strcmp(asan_transform_.instrument_dll_name(), "foo"), 0);
}

TEST_F(AsanTransformTest, SetUseLivenessFlag) {
  EXPECT_FALSE(asan_transform_.use_liveness_analysis());
  asan_transform_.set_use_liveness_analysis(true);
  EXPECT_TRUE(asan_transform_.use_liveness_analysis());
  asan_transform_.set_use_liveness_analysis(false);
  EXPECT_FALSE(asan_transform_.use_liveness_analysis());

  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  EXPECT_FALSE(bb_transform.use_liveness_analysis());
  bb_transform.set_use_liveness_analysis(true);
  EXPECT_TRUE(bb_transform.use_liveness_analysis());
  bb_transform.set_use_liveness_analysis(false);
  EXPECT_FALSE(bb_transform.use_liveness_analysis());
}

TEST_F(AsanTransformTest, SetInterceptCRTFuntionsFlag) {
  EXPECT_FALSE(asan_transform_.use_interceptors());
  asan_transform_.set_use_interceptors(true);
  EXPECT_TRUE(asan_transform_.use_interceptors());
  asan_transform_.set_use_interceptors(false);
  EXPECT_FALSE(asan_transform_.use_interceptors());
}

TEST_F(AsanTransformTest, SetRemoveRedundantChecksFlag) {
  EXPECT_FALSE(asan_transform_.remove_redundant_checks());
  asan_transform_.set_remove_redundant_checks(true);
  EXPECT_TRUE(asan_transform_.remove_redundant_checks());
  asan_transform_.set_remove_redundant_checks(false);
  EXPECT_FALSE(asan_transform_.remove_redundant_checks());

  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  EXPECT_FALSE(bb_transform.remove_redundant_checks());
  bb_transform.set_remove_redundant_checks(true);
  EXPECT_TRUE(bb_transform.remove_redundant_checks());
  bb_transform.set_remove_redundant_checks(false);
  EXPECT_FALSE(bb_transform.remove_redundant_checks());
}

TEST_F(AsanTransformTest, ApplyAsanTransform) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &asan_transform_, &policy_, &block_graph_, dos_header_block_));

  // TODO(sebmarchand): Ensure that each memory access is instrumented by
  // decomposing each block of the new block-graph into basic blocks and walk
  // through their instructions. For now it's not possible due to an issue with
  // the labels in the new block-graph.
}

TEST_F(AsanTransformTest, InjectAsanHooks) {
  // Add a read access to the memory.
  bb_asm_->mov(core::eax, block_graph::Operand(core::ebx));
  // Add a write access to the memory.
  bb_asm_->mov(block_graph::Operand(core::ecx), core::edx);

  // Add source ranges to the instruction.
  block_graph::Instruction& i1 = *basic_block_->instructions().begin();
  Instruction::SourceRange source_range =
      Instruction::SourceRange(RelativeAddress(1000), i1.size());
  i1.set_source_range(source_range);

  // Instrument this basic block.
  InitHooksRefs();
  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(
      basic_block_, AsanBasicBlockTransform::kSafeStackAccess));

  // Ensure that the basic block is instrumented.

  // We had 2 instructions initially, and for each of them we add 3
  // instructions, so we expect to have 2 + 3 * 2 = 8 instructions.
  ASSERT_EQ(basic_block_->instructions().size(), 8);

  // Walk through the instructions to ensure that the Asan hooks have been
  // injected.
  BasicBlock::Instructions::const_iterator iter_inst =
      basic_block_->instructions().begin();

  Instruction::SourceRange empty_source_range;
  ASSERT_TRUE(empty_source_range != source_range);

  // First we check if the first memory access is instrumented as a 4 byte read
  // access. We also validate that the instrumentation has not had source range
  // information added.
  ASSERT_EQ(empty_source_range, iter_inst->source_range());
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_PUSH);
  ASSERT_EQ(empty_source_range, iter_inst->source_range());
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_LEA);
  ASSERT_EQ(empty_source_range, iter_inst->source_range());
  ASSERT_EQ(iter_inst->references().size(), 1);
  HookMapEntryKey check_4_byte_read_key =
      { AsanBasicBlockTransform::kReadAccess, 4, 0, true };
  ASSERT_TRUE(iter_inst->references().begin()->second.block()
      == hooks_check_access_[check_4_byte_read_key]);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_CALL);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_MOV);

  // Then we check if the second memory access is well instrumented as a 4 byte
  // write access.
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_PUSH);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_LEA);
  ASSERT_EQ(iter_inst->references().size(), 1);
  HookMapEntryKey check_4_byte_write_key =
      { AsanBasicBlockTransform::kWriteAccess, 4, 0, true };
  ASSERT_TRUE(iter_inst->references().begin()->second.block()
      == hooks_check_access_[check_4_byte_write_key]);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_CALL);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_MOV);

  ASSERT_TRUE(iter_inst == basic_block_->instructions().end());
}

TEST_F(AsanTransformTest, InjectAsanHooksWithSourceRange) {
  // Add a read access to the memory.
  bb_asm_->mov(core::eax, block_graph::Operand(core::ebx));

  // Add a source range to the instruction.
  block_graph::Instruction& i1 = *basic_block_->instructions().begin();
  Instruction::SourceRange source_range =
      Instruction::SourceRange(RelativeAddress(1000), i1.size());
  i1.set_source_range(source_range);

  // Keep track of basic block size.
  uint32 before_instructions_count = basic_block_->instructions().size();

  // Instrument this basic block.
  InitHooksRefs();
  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  bb_transform.set_debug_friendly(true);

  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(
        basic_block_, AsanBasicBlockTransform::kSafeStackAccess));

  // Ensure this basic block is instrumented.
  uint32 after_instructions_count = basic_block_->instructions().size();
  ASSERT_LT(before_instructions_count, after_instructions_count);

  // Walk through the instructions and validate the source range.
  BasicBlock::Instructions::const_iterator iter_inst =
      basic_block_->instructions().begin();

  for ( ; iter_inst != basic_block_->instructions().end(); ++iter_inst)
    EXPECT_EQ(source_range, iter_inst->source_range());
}

TEST_F(AsanTransformTest, InstrumentDifferentKindOfInstructions) {
  uint32 instrumentable_instructions = 0;

  // Generate a bunch of instrumentable and non instrumentable instructions.
  bb_asm_->mov(core::eax, block_graph::Operand(core::ebx));
  instrumentable_instructions++;
  bb_asm_->mov(block_graph::Operand(core::ecx), core::edx);
  instrumentable_instructions++;
  bb_asm_->call(block_graph::Operand(core::ecx));
  instrumentable_instructions++;
  bb_asm_->jmp(block_graph::Operand(core::ecx));
  instrumentable_instructions++;
  bb_asm_->push(block_graph::Operand(core::eax));
  instrumentable_instructions++;

  // Non-instrumentable.
  bb_asm_->lea(core::eax, block_graph::Operand(core::ecx));

  uint32 expected_instructions_count = basic_block_->instructions().size()
      + 3 * instrumentable_instructions;
  // Instrument this basic block.
  InitHooksRefs();
  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(
      basic_block_, AsanBasicBlockTransform::kSafeStackAccess));
  ASSERT_EQ(basic_block_->instructions().size(), expected_instructions_count);
}

TEST_F(AsanTransformTest, InstrumentAndRemoveRedundantChecks) {
  uint32 instrumentable_instructions = 0;

  // Generate a bunch of instrumentable and non instrumentable instructions.
  // We generate operand [ecx] multiple time as a redundant memory access.
  bb_asm_->mov(core::eax, block_graph::Operand(core::ecx));
  instrumentable_instructions++;
  bb_asm_->mov(block_graph::Operand(core::ecx), core::edx);
  // Validate that indirect call clear the memory state.
  bb_asm_->call(block_graph::Operand(core::ecx));
  bb_asm_->push(block_graph::Operand(core::eax));
  instrumentable_instructions++;
  bb_asm_->mov(core::eax, block_graph::Operand(core::ecx));
  instrumentable_instructions++;
  bb_asm_->jmp(block_graph::Operand(core::ecx));

  uint32 expected_instructions_count = basic_block_->instructions().size()
      + 3 * instrumentable_instructions;
  // Instrument this basic block.
  InitHooksRefs();
  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  bb_transform.set_remove_redundant_checks(true);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(
      basic_block_, AsanBasicBlockTransform::kSafeStackAccess));
  ASSERT_EQ(basic_block_->instructions().size(), expected_instructions_count);
}

TEST_F(AsanTransformTest, NonInstrumentableStackBasedInstructions) {
  // DEC DWORD [EBP - 0x2830]
  static const uint8 kDec1[6] = { 0xff, 0x8d, 0xd0, 0xd7, 0xff, 0xff };
  // INC DWORD [EBP - 0x31c]
  static const uint8 kInc1[6] = { 0xff, 0x85, 0xe4, 0xfc, 0xff, 0xff };
  // INC DWORD [ESP + 0x1c]
  static const uint8 kInc2[4] = { 0xff, 0x44, 0x24, 0x1c };
  // NEG DWORD [EBP + 0x24]
  static const uint8 kNeg1[3] = { 0xf7, 0x5d, 0x24 };
  // FILD QWORD [EBP - 0x8]
  static const uint8 kFild1[3] = { 0xdf, 0x6d, 0xf8 };
  // FISTP QWORD [ESP + 0x28]
  static const uint8 kFistp1[4] = { 0xdf, 0x7c, 0x24, 0x28 };
  // MOV EDI, [EBP - 0x4]
  static const uint8 kMov1[3] = { 0x8b, 0x7d, 0xfc };
  // MOV EAX, [EBP - 0x104]
  static const uint8 kMov2[6] = { 0x8b, 0x85, 0xfc, 0xfe, 0xff, 0xff };

  ASSERT_TRUE(AddInstructionFromBuffer(kDec1, sizeof(kDec1)));
  ASSERT_TRUE(AddInstructionFromBuffer(kInc1, sizeof(kInc1)));
  ASSERT_TRUE(AddInstructionFromBuffer(kInc2, sizeof(kInc2)));
  ASSERT_TRUE(AddInstructionFromBuffer(kNeg1, sizeof(kNeg1)));
  ASSERT_TRUE(AddInstructionFromBuffer(kFild1, sizeof(kFild1)));
  ASSERT_TRUE(AddInstructionFromBuffer(kFistp1, sizeof(kFistp1)));
  ASSERT_TRUE(AddInstructionFromBuffer(kMov1, sizeof(kMov1)));
  ASSERT_TRUE(AddInstructionFromBuffer(kMov2, sizeof(kMov2)));

  // Keep track of the basic block size before Asan transform.
  uint32 expected_basic_block_size = basic_block_->instructions().size();

  // Instrument this basic block.
  InitHooksRefs();
  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(
        basic_block_, AsanBasicBlockTransform::kSafeStackAccess));

  // Non-instrumentable instructions implies no change.
  EXPECT_EQ(expected_basic_block_size, basic_block_->instructions().size());
}

TEST_F(AsanTransformTest, InstrumentableStackBasedUnsafeInstructions) {
  // DEC DWORD [EBP - 0x2830]
  static const uint8 kDec1[6] = { 0xff, 0x8d, 0xd0, 0xd7, 0xff, 0xff };

  ASSERT_TRUE(AddInstructionFromBuffer(kDec1, sizeof(kDec1)));

  // Keep track of the basic block size before Asan transform.
  uint32 previous_basic_block_size = basic_block_->instructions().size();

  // Instrument this basic block considering invalid stack manipulation.
  InitHooksRefs();
  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(
        basic_block_, AsanBasicBlockTransform::kUnsafeStackAccess));

  // This instruction should have been instrumented, and we must observe
  // a increase in size.
  EXPECT_LT(previous_basic_block_size, basic_block_->instructions().size());
}

TEST_F(AsanTransformTest, NonInstrumentableSegmentBasedInstructions) {
  // add eax, fs:[eax]
  static const uint8 kAdd1[3] = { 0x64, 0x03, 0x00 };
  // inc gs:[eax]
  static const uint8 kInc1[3] = { 0x65, 0xFE, 0x00 };

  ASSERT_TRUE(AddInstructionFromBuffer(kAdd1, sizeof(kAdd1)));
  ASSERT_TRUE(AddInstructionFromBuffer(kInc1, sizeof(kInc1)));

  // Keep track of the basic block size before Asan transform.
  uint32 expected_basic_block_size = basic_block_->instructions().size();

  // Instrument this basic block.
  InitHooksRefs();
  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(
        basic_block_,
        AsanBasicBlockTransform::kSafeStackAccess));

  // Non-instrumentable instructions implies no change.
  EXPECT_EQ(expected_basic_block_size, basic_block_->instructions().size());
}

TEST_F(AsanTransformTest, FilteredInstructionsNotInstrumented) {
  // Add a read access to the memory.
  bb_asm_->mov(core::eax, block_graph::Operand(core::ebx));
  // Add a write access to the memory.
  bb_asm_->mov(block_graph::Operand(core::ecx), core::edx);

  // Add a source range to the first instruction.
  block_graph::Instruction& i1 = *basic_block_->instructions().begin();
  i1.set_source_range(Instruction::SourceRange(
      RelativeAddress(1000), i1.size()));

  // Create a filter that blocks out that source range.
  RelativeAddressFilter filter(
      RelativeAddressFilter::Range(RelativeAddress(0), 2000));
  filter.Mark(RelativeAddressFilter::Range(RelativeAddress(995), 50));

  // Pass the filter to the BB transform.
  InitHooksRefs();
  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  bb_transform.set_filter(&filter);

  // Instrument this basic block.
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(
        basic_block_, AsanBasicBlockTransform::kSafeStackAccess));

  // Ensure that the basic block is instrumented, but only the second
  // instruction.

  // We had 2 instructions initially. For the second one we add 3
  // instructions, so we expect to have 1 + (1 + 3) = 5 instructions.
  ASSERT_EQ(basic_block_->instructions().size(), 5);

  // Walk through the instructions to ensure that the Asan hooks have been
  // injected.
  BasicBlock::Instructions::const_iterator iter_inst =
      basic_block_->instructions().begin();

  // Ensure the first instruction is not instrumented at all.
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_MOV);

  // Then we check if the second memory access is well instrumented as a 4 byte
  // write access.
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_PUSH);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_LEA);
  ASSERT_EQ(iter_inst->references().size(), 1);
  HookMapEntryKey check_4_byte_write_key =
      { AsanBasicBlockTransform::kWriteAccess, 4, 0, true };
  ASSERT_TRUE(iter_inst->references().begin()->second.block()
      == hooks_check_access_[check_4_byte_write_key]);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_CALL);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_MOV);

  ASSERT_TRUE(iter_inst == basic_block_->instructions().end());
}

TEST_F(AsanTransformTest, InstrumentableStringInstructions) {
  static const uint8 movsd[1] = { 0xA5 };
  static const uint8 movsw[2] = { 0x66, 0xA5 };
  static const uint8 movsb[1] = { 0xA4 };

  static const uint8 cmpsd[1] = { 0xA7 };
  static const uint8 cmpsw[2] = { 0x66, 0xA7 };
  static const uint8 cmpsb[1] = { 0xA6 };

  static const uint8 stosd[1] = { 0xAB };
  static const uint8 stosw[2] = { 0x66, 0xAB };
  static const uint8 stosb[1] = { 0xAA };

  EXPECT_TRUE(AddInstructionFromBuffer(movsd, sizeof(movsd)));
  EXPECT_TRUE(AddInstructionFromBuffer(movsw, sizeof(movsw)));
  EXPECT_TRUE(AddInstructionFromBuffer(movsb, sizeof(movsb)));
  EXPECT_TRUE(AddInstructionFromBuffer(cmpsd, sizeof(cmpsd)));
  EXPECT_TRUE(AddInstructionFromBuffer(cmpsw, sizeof(cmpsw)));
  EXPECT_TRUE(AddInstructionFromBuffer(cmpsb, sizeof(cmpsb)));
  EXPECT_TRUE(AddInstructionFromBuffer(stosd, sizeof(stosd)));
  EXPECT_TRUE(AddInstructionFromBuffer(stosw, sizeof(stosw)));
  EXPECT_TRUE(AddInstructionFromBuffer(stosb, sizeof(stosb)));

  // Keep number of instrumentable instructions.
  uint32 count_instructions = basic_block_->instructions().size();

  // Keep track of the basic block size before Asan transform.
  uint32 basic_block_size = basic_block_->instructions().size();

  // Instrument this basic block.
  InitHooksRefs();
  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(
        basic_block_, AsanBasicBlockTransform::kSafeStackAccess));

  // Each instrumentable instructions implies 1 new instructions.
  uint32 expected_basic_block_size = count_instructions + basic_block_size;

  // Validate basic block size.
  ASSERT_EQ(basic_block_->instructions().size(), expected_basic_block_size);
}

TEST_F(AsanTransformTest, InstrumentableRepzStringInstructions) {
  static const uint8 movsd[2] = { 0xF3, 0xA5 };
  static const uint8 movsw[3] = { 0xF3, 0x66, 0xA5 };
  static const uint8 movsb[2] = { 0xF3, 0xA4 };

  static const uint8 cmpsd[2] = { 0xF3, 0xA7 };
  static const uint8 cmpsw[3] = { 0xF3, 0x66, 0xA7 };
  static const uint8 cmpsb[2] = { 0xF3, 0xA6 };

  static const uint8 stosd[2] = { 0xF3, 0xAB };
  static const uint8 stosw[3] = { 0xF3, 0x66, 0xAB };
  static const uint8 stosb[2] = { 0xF3, 0xAA };

  EXPECT_TRUE(AddInstructionFromBuffer(movsd, sizeof(movsd)));
  EXPECT_TRUE(AddInstructionFromBuffer(movsw, sizeof(movsw)));
  EXPECT_TRUE(AddInstructionFromBuffer(movsb, sizeof(movsb)));
  EXPECT_TRUE(AddInstructionFromBuffer(cmpsd, sizeof(cmpsd)));
  EXPECT_TRUE(AddInstructionFromBuffer(cmpsw, sizeof(cmpsw)));
  EXPECT_TRUE(AddInstructionFromBuffer(cmpsb, sizeof(cmpsb)));
  EXPECT_TRUE(AddInstructionFromBuffer(stosd, sizeof(stosd)));
  EXPECT_TRUE(AddInstructionFromBuffer(stosw, sizeof(stosw)));
  EXPECT_TRUE(AddInstructionFromBuffer(stosb, sizeof(stosb)));

  // Keep number of instrumentable instructions.
  uint32 count_instructions = basic_block_->instructions().size();

  // Keep track of the basic block size before Asan transform.
  uint32 basic_block_size = basic_block_->instructions().size();

  // Instrument this basic block.
  InitHooksRefs();
  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(
        basic_block_, AsanBasicBlockTransform::kSafeStackAccess));

  // Each instrumentable instructions implies 1 new instructions.
  uint32 expected_basic_block_size = count_instructions + basic_block_size;

  // Validate basic block size.
  ASSERT_EQ(basic_block_->instructions().size(), expected_basic_block_size);
}

namespace {

using base::win::PEImage;
typedef std::set<std::string> StringSet;
typedef std::set<void*> FunctionsIATAddressSet;
typedef std::vector<std::string> StringVector;

const char kAsanRtlDll[] = "syzyasan_rtl.dll";

bool EnumKernel32HeapImports(const PEImage &image,
                             const char* module,
                             unsigned long ordinal,
                             const char* name,
                             unsigned long hint,
                             PIMAGE_THUNK_DATA iat,
                             void* cookie) {
  DCHECK(module != NULL);
  DCHECK(cookie != NULL);

  StringVector* modules = reinterpret_cast<StringVector*>(cookie);

  if (_stricmp("kernel32.dll", module) == 0 && strncmp("Heap", name, 4) == 0) {
    DCHECK(name != NULL);
    modules->push_back(name);
  }

  return true;
}

bool EnumKernel32InterceptedFunctionsImports(const PEImage &image,
                                             const char* module,
                                             unsigned long ordinal,
                                             const char* name,
                                             unsigned long hint,
                                             PIMAGE_THUNK_DATA iat,
                                             void* cookie) {
  DCHECK(module != NULL);
  DCHECK(cookie != NULL);

  StringVector* modules = reinterpret_cast<StringVector*>(cookie);
  static const char* kInterceptedFunctions[] = {
    "GetProcessHeap",
    "ReadFile",
    "WriteFile",
  };

  if (_stricmp("kernel32.dll", module) == 0) {
    for (size_t i = 0; i < arraysize(kInterceptedFunctions); ++i) {
      if (base::strcasecmp(kInterceptedFunctions[i], name) == 0) {
        DCHECK(name != NULL);
        modules->push_back(name);
        return true;
      }
    }
  }

  return true;
}

bool EnumAsanImports(const PEImage &image,
                     const char* module,
                     unsigned long ordinal,
                     const char* name,
                     unsigned long hint,
                     PIMAGE_THUNK_DATA iat,
                     void* cookie) {
  DCHECK(module != NULL);
  DCHECK(cookie != NULL);

  StringSet* modules = reinterpret_cast<StringSet*>(cookie);

  if (strcmp(kAsanRtlDll, module) == 0) {
    DCHECK(name != NULL);
    modules->insert(name);
  }

  return true;
}

bool GetAsanHooksIATEntries(const PEImage &image,
                            const char* module,
                            unsigned long ordinal,
                            const char* name,
                            unsigned long hint,
                            PIMAGE_THUNK_DATA iat,
                            void* cookie) {
  DCHECK(module != NULL);
  DCHECK(cookie != NULL);

  FunctionsIATAddressSet* hooks_iat_entries =
      reinterpret_cast<FunctionsIATAddressSet*>(cookie);

  if (strcmp(kAsanRtlDll, module) != 0)
    return true;

  DCHECK(name != NULL);

  // Ensures that the function is an asan_check_access hook.
  if (StartsWithASCII(name, "asan_check_", true /* case sensitive */))
    hooks_iat_entries->insert(reinterpret_cast<PVOID>(iat->u1.Function));

  return true;
}

}  // namespace

TEST_F(AsanTransformTest, ImportsAreRedirected) {
  base::FilePath asan_instrumented_dll = testing::GetExeTestDataRelativePath(
      testing::kAsanInstrumentedTestDllName);

  // Load the transformed module without resolving its dependencies.
  base::NativeLibrary lib =
      ::LoadLibraryEx(asan_instrumented_dll.value().c_str(),
                      NULL,
                      DONT_RESOLVE_DLL_REFERENCES);
  ASSERT_TRUE(lib != NULL);
  // Make sure it's unloaded on failure.
  base::ScopedNativeLibrary lib_keeper(lib);

  PEImage image(lib);
  ASSERT_TRUE(image.VerifyMagic());
  StringSet imports;
  ASSERT_TRUE(image.EnumAllImports(&EnumAsanImports, &imports));

  StringVector heap_imports;
  ASSERT_TRUE(image.EnumAllImports(&EnumKernel32HeapImports, &heap_imports));
  StringVector intercepted_functions_imports;
  ASSERT_TRUE(image.EnumAllImports(&EnumKernel32InterceptedFunctionsImports,
                                   &intercepted_functions_imports));

  // This isn't strictly speaking a full test, as we only check that the new
  // imports have been added. It's however more trouble than it's worth to
  // test this fully for now.
  StringSet expected;
  for (size_t i = 0; i < heap_imports.size(); ++i) {
    std::string asan_import = "asan_";
    asan_import.append(heap_imports[i]);
    expected.insert(asan_import);
  }
  for (size_t i = 0; i < intercepted_functions_imports.size(); ++i) {
    std::string asan_import = "asan_";
    asan_import.append(intercepted_functions_imports[i]);
    expected.insert(asan_import);
  }
  expected.insert("asan_check_1_byte_read_access");
  expected.insert("asan_check_2_byte_read_access");
  expected.insert("asan_check_4_byte_read_access");
  expected.insert("asan_check_8_byte_read_access");
  expected.insert("asan_check_10_byte_read_access");
  expected.insert("asan_check_16_byte_read_access");
  expected.insert("asan_check_32_byte_read_access");
  expected.insert("asan_check_1_byte_write_access");
  expected.insert("asan_check_2_byte_write_access");
  expected.insert("asan_check_4_byte_write_access");
  expected.insert("asan_check_8_byte_write_access");
  expected.insert("asan_check_10_byte_write_access");
  expected.insert("asan_check_16_byte_write_access");
  expected.insert("asan_check_32_byte_write_access");

  expected.insert("asan_check_1_byte_read_access_no_flags");
  expected.insert("asan_check_2_byte_read_access_no_flags");
  expected.insert("asan_check_4_byte_read_access_no_flags");
  expected.insert("asan_check_8_byte_read_access_no_flags");
  expected.insert("asan_check_10_byte_read_access_no_flags");
  expected.insert("asan_check_16_byte_read_access_no_flags");
  expected.insert("asan_check_32_byte_read_access_no_flags");
  expected.insert("asan_check_1_byte_write_access_no_flags");
  expected.insert("asan_check_2_byte_write_access_no_flags");
  expected.insert("asan_check_4_byte_write_access_no_flags");
  expected.insert("asan_check_8_byte_write_access_no_flags");
  expected.insert("asan_check_10_byte_write_access_no_flags");
  expected.insert("asan_check_16_byte_write_access_no_flags");
  expected.insert("asan_check_32_byte_write_access_no_flags");

  expected.insert("asan_check_repz_4_byte_cmps_access");
  expected.insert("asan_check_repz_4_byte_movs_access");
  expected.insert("asan_check_repz_4_byte_stos_access");
  expected.insert("asan_check_repz_2_byte_cmps_access");
  expected.insert("asan_check_repz_2_byte_movs_access");
  expected.insert("asan_check_repz_2_byte_stos_access");
  expected.insert("asan_check_repz_1_byte_cmps_access");
  expected.insert("asan_check_repz_1_byte_movs_access");
  expected.insert("asan_check_repz_1_byte_stos_access");

  expected.insert("asan_check_4_byte_cmps_access");
  expected.insert("asan_check_4_byte_movs_access");
  expected.insert("asan_check_4_byte_stos_access");
  expected.insert("asan_check_2_byte_cmps_access");
  expected.insert("asan_check_2_byte_movs_access");
  expected.insert("asan_check_2_byte_stos_access");
  expected.insert("asan_check_1_byte_cmps_access");
  expected.insert("asan_check_1_byte_movs_access");
  expected.insert("asan_check_1_byte_stos_access");

  expected.insert("asan_memcpy");
  expected.insert("asan_memmove");
  expected.insert("asan_memset");
  expected.insert("asan_memchr");
  expected.insert("asan_strcspn");
  expected.insert("asan_strlen");
  expected.insert("asan_strrchr");
  expected.insert("asan_strcmp");
  expected.insert("asan_strpbrk");
  expected.insert("asan_strstr");
  expected.insert("asan_strspn");
  expected.insert("asan_strncpy");
  expected.insert("asan_strncat");
  expected.insert("asan_wcsrchr");

  EXPECT_EQ(expected, imports);
}

TEST_F(AsanTransformTest, AsanHooksAreStubbed) {
  base::FilePath asan_instrumented_dll = testing::GetExeTestDataRelativePath(
      testing::kAsanInstrumentedTestDllName);

  // Load the transformed module without resolving its dependencies.
  base::NativeLibrary lib =
      ::LoadLibraryEx(asan_instrumented_dll.value().c_str(),
                      NULL,
                      DONT_RESOLVE_DLL_REFERENCES);
  ASSERT_TRUE(lib != NULL);
  // Make sure it's unloaded on failure.
  base::ScopedNativeLibrary lib_keeper(lib);

  PEImage image(lib);
  ASSERT_TRUE(image.VerifyMagic());

  // Iterate over the image import descriptors. We want to make sure the
  // one for syzyasan_rtl.dll is bound.
  DWORD size = image.GetImageDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_IMPORT);
  PIMAGE_IMPORT_DESCRIPTOR iid = image.GetFirstImportChunk();
  ASSERT_TRUE(iid != NULL);
  ASSERT_GE(size, sizeof(IMAGE_IMPORT_DESCRIPTOR));
  for (; iid->FirstThunk; ++iid) {
    std::string module_name(reinterpret_cast<LPCSTR>(
        image.RVAToAddr(iid->Name)));
    if (module_name == kAsanRtlDll)
      ASSERT_NE(0u, iid->TimeDateStamp);
  }

  // As all the hooks may refer to only two kinds of stubs, we expect to have
  // exactly two entries in the set.
  FunctionsIATAddressSet hooks_iat_set;
  ASSERT_TRUE(image.EnumAllImports(&GetAsanHooksIATEntries, &hooks_iat_set));
  ASSERT_EQ(hooks_iat_set.size(), 2U);

  // Ensures that all stubs are in the thunks section.
  FunctionsIATAddressSet::iterator hook = hooks_iat_set.begin();
  for (; hook != hooks_iat_set.end(); ++hook) {
    PVOID stub_address = *hook;
    PIMAGE_SECTION_HEADER stub_sec =
        image.GetImageSectionFromAddr(stub_address);
    ASSERT_STREQ(common::kThunkSectionName,
                 reinterpret_cast<const char*>(stub_sec->Name));
  }
}

TEST_F(AsanTransformTest, InterceptFunctions) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  BlockGraph::Block* b1 =
      block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "testAsan_b1");
  BlockGraph::Block* b2 =
      block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "testAsan_b2");
  BlockGraph::Block* b3 =
      block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "testAsan_b3");
  ASSERT_TRUE(b1 != NULL);
  ASSERT_TRUE(b2 != NULL);
  ASSERT_TRUE(b3 != NULL);

  ASSERT_TRUE(b1->references().empty());
  ASSERT_TRUE(b1->referrers().empty());
  ASSERT_TRUE(b2->references().empty());
  ASSERT_TRUE(b2->referrers().empty());
  ASSERT_TRUE(b3->references().empty());
  ASSERT_TRUE(b3->referrers().empty());

  // Add a reference from b2 to b1 and from b3 to b1.
  BlockGraph::Reference ref_b2_b1(BlockGraph::PC_RELATIVE_REF, 1, b1, 0, 0);
  BlockGraph::Reference ref_b3_b1(BlockGraph::PC_RELATIVE_REF, 1, b1, 1, 1);
  ASSERT_TRUE(b2->SetReference(0, ref_b2_b1));
  ASSERT_TRUE(b3->SetReference(1, ref_b3_b1));

  EXPECT_EQ(2U, b1->referrers().size());

  pe::transforms::ImportedModule import_module("foo.dll");

  size_t num_blocks_pre_transform = block_graph_.blocks().size();
  size_t num_sections_pre_transform = block_graph_.sections().size();
  // Intercept the calls to b1.
  TestAsanTransform::FunctionInterceptionSet function_set;
  function_set.insert("testAsan_b1");
  EXPECT_TRUE(asan_transform_.InterceptFunctions(&import_module,
                                                 &policy_,
                                                 &block_graph_,
                                                 dos_header_block_,
                                                 function_set));

  // The block graph should have grown by 3 blocks:
  //     - the Import Address Table (IAT),
  //     - the Import Name Table (INT),
  //     - the thunk.
  EXPECT_EQ(num_blocks_pre_transform + 3, block_graph_.blocks().size());

  // The .thunks section should have been added.
  EXPECT_EQ(num_sections_pre_transform + 1, block_graph_.sections().size());

  BlockGraph::Section* thunk_section = block_graph_.FindSection(
      common::kThunkSectionName);
  EXPECT_TRUE(thunk_section != NULL);

  const BlockGraph::Block* block_in_thunk_section = NULL;
  BlockGraph::BlockMap::const_iterator iter_blocks =
      block_graph_.blocks().begin();
  for (; iter_blocks != block_graph_.blocks().end(); ++iter_blocks) {
    if (iter_blocks->second.section() == thunk_section->id()) {
      // There should be only one block in the thunk section.
      EXPECT_TRUE(block_in_thunk_section == NULL);
      block_in_thunk_section = &iter_blocks->second;
    }
  }

  // Only the entry in the IAT should refer to b1.
  EXPECT_EQ(1U, b1->referrers().size());
}

}  // namespace transforms
}  // namespace instrument
