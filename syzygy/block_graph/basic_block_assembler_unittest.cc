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
#include "syzygy/block_graph/basic_block_assembler.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_subgraph.h"

namespace block_graph {

namespace {

class BasicBlockAssemblerTest : public testing::Test {
 public:
  typedef BlockGraph::RelativeAddress RelativeAddress;
  typedef BlockGraph::Block::SourceRange SourceRange;

  BasicBlockAssemblerTest();

  void SetUp() override {}

  void TearDown() override {}

 protected:
  struct Ref {
    size_t offset;
    BasicBlockReference::ReferredType type;
    const void* reference;
  };

  template <size_t N>
  void AssertRefs(const Ref(& refs)[N]) {
    ASSERT_EQ(1, instructions_.size());
    const Instruction& instr = instructions_.front();

    for (size_t i = 0; i < N; ++i) {
      BasicBlock::BasicBlockReferenceMap::const_iterator it =
          instr.references().find(refs[i].offset);
      ASSERT_NE(instr.references().end(), it);
      ASSERT_EQ(refs[i].type, it->second.referred_type());
      switch (refs[i].type) {
        case BasicBlockReference::REFERRED_TYPE_BLOCK:
          ASSERT_EQ(refs[i].reference, it->second.block());
          break;
        case BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK:
          ASSERT_EQ(refs[i].reference, it->second.basic_block());
          break;
        default:
          ASSERT_TRUE(false);
      }

      ASSERT_EQ(refs[i].type, it->second.referred_type());
    }

    instructions_.clear();
  }

  void AssertNoRefs() {
    ASSERT_EQ(1, instructions_.size());
    ASSERT_EQ(0, instructions_.front().references().size());
    instructions_.clear();
  }

  BlockGraph block_graph_;
  BlockGraph::Block* test_block_;
  BasicBlockSubGraph subgraph_;
  BasicCodeBlock* test_bb_;
  BasicBlock::Instructions instructions_;
  BasicBlockAssembler asm_;
};

#define ASSERT_REFS(...) \
  do { \
    const Ref refs[] = { __VA_ARGS__ }; \
    ASSERT_NO_FATAL_FAILURE(AssertRefs(refs)); \
  } while (0)

#define ASSERT_NO_REFS() ASSERT_NO_FATAL_FAILURE(AssertNoRefs())

BasicBlockAssemblerTest::BasicBlockAssemblerTest()
    : test_block_(NULL),
      test_bb_(NULL),
      asm_(instructions_.end(), &instructions_) {
  test_block_ = block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 10, "test block");
  test_bb_ = subgraph_.AddBasicCodeBlock("foo");
}

}  // namespace

TEST(UntypedReferenceTest, DefaultConstructor) {
  UntypedReference r;
  EXPECT_EQ(NULL, r.basic_block());
  EXPECT_EQ(NULL, r.block());
  EXPECT_EQ(0, r.offset());
  EXPECT_EQ(0, r.base());
  EXPECT_FALSE(r.IsValid());
  EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_UNKNOWN, r.referred_type());
}

TEST(UntypedReferenceTest, BasicBlockReferenceToBasicBlockConstructor) {
  BasicBlockSubGraph subgraph;
  BasicCodeBlock* bcb = subgraph.AddBasicCodeBlock("foo");
  BasicBlock* bb = bcb;
  BasicBlockReference bbref(BlockGraph::ABSOLUTE_REF, 4, bcb);
  UntypedReference r(bbref);
  EXPECT_EQ(bb, r.basic_block());
  EXPECT_EQ(NULL, r.block());
  EXPECT_EQ(0, r.offset());
  EXPECT_EQ(0, r.base());
  EXPECT_TRUE(r.IsValid());
  EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK, r.referred_type());
}

TEST(UntypedReferenceTest, BasicBlockReferenceToBlockConstructor) {
  BlockGraph block_graph;
  BlockGraph::Block* b =
      block_graph.AddBlock(BlockGraph::CODE_BLOCK, 20, "foo");
  BasicBlockReference bbref(BlockGraph::ABSOLUTE_REF, 4, b, 4, 10);
  UntypedReference r(bbref);
  EXPECT_EQ(NULL, r.basic_block());
  EXPECT_EQ(b, r.block());
  EXPECT_EQ(4, r.offset());
  EXPECT_EQ(10, r.base());
  EXPECT_TRUE(r.IsValid());
  EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_BLOCK, r.referred_type());
}

TEST(UntypedReferenceTest, BasicBlockConstructor) {
  BasicBlockSubGraph subgraph;
  BasicCodeBlock* bcb = subgraph.AddBasicCodeBlock("foo");
  BasicBlock* bb = bcb;
  UntypedReference r(bcb);
  EXPECT_EQ(bb, r.basic_block());
  EXPECT_EQ(NULL, r.block());
  EXPECT_EQ(0, r.offset());
  EXPECT_EQ(0, r.base());
  EXPECT_TRUE(r.IsValid());
  EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK, r.referred_type());
}

TEST(UntypedReferenceTest, BlockConstructor) {
  BlockGraph block_graph;
  BlockGraph::Block* b =
      block_graph.AddBlock(BlockGraph::CODE_BLOCK, 0, "dummy");
  UntypedReference r(b, 4, 10);
  EXPECT_EQ(NULL, r.basic_block());
  EXPECT_EQ(b, r.block());
  EXPECT_EQ(4, r.offset());
  EXPECT_EQ(10, r.base());
  EXPECT_TRUE(r.IsValid());
  EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_BLOCK, r.referred_type());
}

TEST(UntypedReferenceTest, CopyConstructor) {
  BlockGraph block_graph;
  BlockGraph::Block* b =
      block_graph.AddBlock(BlockGraph::CODE_BLOCK, 0, "dummy");
  UntypedReference r1(b, 4, 10);

  UntypedReference r2(r1);
  EXPECT_EQ(r1.basic_block(), r2.basic_block());
  EXPECT_EQ(r1.block(), r2.block());
  EXPECT_EQ(r1.offset(), r2.offset());
  EXPECT_EQ(r1.base(), r2.base());
  EXPECT_EQ(r1.IsValid(), r2.IsValid());
}

TEST(UntypedReferenceTest, Comparison) {
  BlockGraph block_graph;
  BasicBlockSubGraph subgraph;
  BlockGraph::Block* b =
      block_graph.AddBlock(BlockGraph::CODE_BLOCK, 0, "dummy");
  UntypedReference r1(b, 4, 10);

  UntypedReference r2(b, 0, 0);
  EXPECT_FALSE(r1 == r2);

  BasicCodeBlock* bcb = subgraph.AddBasicCodeBlock("foo");
  UntypedReference r3(bcb);
  EXPECT_FALSE(r1 == r3);
  EXPECT_FALSE(r2 == r3);

  UntypedReference r4(r1);
  EXPECT_TRUE(r1 == r4);

  UntypedReference r5(r2);
  EXPECT_TRUE(r2 == r5);
}

namespace {

template <typename ValueTraits>
class ValueTest : public BasicBlockAssemblerTest {
 public:
  typedef typename ValueTraits ValueTraits;
  typedef typename ValueTraits::ValueType ValueType;

  void TestValue(const ValueType& value,
                 uint32_t expected_value,
                 assm::ValueSize expected_size) {
    EXPECT_EQ(expected_size, value.size());
    EXPECT_EQ(expected_value, value.value());
    EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_UNKNOWN,
              value.reference().referred_type());

    auto value_copy(value);
    EXPECT_EQ(expected_size, value_copy.size());
    EXPECT_EQ(expected_value, value_copy.value());
    EXPECT_EQ(BasicBlockReference::REFERRED_TYPE_UNKNOWN,
              value_copy.reference().referred_type());

    EXPECT_TRUE(value == value_copy);

    auto value_diff(ValueTraits::Factory(expected_value - 1));
    EXPECT_FALSE(value == value_diff);
  }

  void Test8BitValue(uint32_t input_value, uint32_t expected_value) {
    TestValue(ValueTraits::Factory(input_value),
              expected_value, assm::kSize8Bit);
    TestValue(ValueTraits::Factory(input_value, assm::kSize8Bit),
              expected_value, assm::kSize8Bit);
  }

  void Test32BitValue(uint32_t input_value, uint32_t expected_value) {
    TestValue(ValueTraits::Factory(input_value),
              expected_value, assm::kSize32Bit);
    TestValue(ValueTraits::Factory(input_value, assm::kSize32Bit),
              expected_value, assm::kSize32Bit);
  }
};

struct ImmediateTestTraits {
  typedef BasicBlockAssembler::Immediate ValueType;

  static ValueType Factory() { return Immediate(); }
  static ValueType Factory(uint32_t value) { return Immediate(value); }
  static ValueType Factory(uint32_t value, assm::ValueSize size) {
    return Immediate(value, size);
  }
  static ValueType Factory(BasicBlock* bb) { return Immediate(bb); }
  static ValueType Factory(BlockGraph::Block* block,
                           BlockGraph::Offset offset) {
    return Immediate(block, offset);
  }
  static ValueType Factory(BlockGraph::Block* block,
                           BlockGraph::Offset offset,
                           BlockGraph::Offset base) {
    return Immediate(block, offset, base);
  }
  static ValueType Factory(uint32_t value,
                           ValueSize size,
                           const UntypedReference& ref) {
    return Immediate(value, size, ref);
  }
};

struct DisplacementTestTraits {
  typedef BasicBlockAssembler::Displacement ValueType;

  static ValueType Factory() { return Displacement(); }
  static ValueType Factory(uint32_t value) { return Displacement(value); }
  static ValueType Factory(uint32_t value, assm::ValueSize size) {
    return Displacement(value, size);
  }
  static ValueType Factory(BasicBlock* bb) { return Displacement(bb); }
  static ValueType Factory(BlockGraph::Block* block,
                           BlockGraph::Offset offset) {
    return Displacement(block, offset);
  }
  static ValueType Factory(BlockGraph::Block* block,
                           BlockGraph::Offset offset,
                           BlockGraph::Offset base) {
    return Displacement(block, offset, base);
  }
  static ValueType Factory(uint32_t value,
                           ValueSize size,
                           const UntypedReference& ref) {
    return Displacement(value, size, ref);
  }
};

}  // namespace

typedef ::testing::Types<ImmediateTestTraits, DisplacementTestTraits>
    ValueTestTypes;
TYPED_TEST_CASE(ValueTest, ValueTestTypes);

TYPED_TEST(ValueTest, Factories) {
  {
    auto imm_empty(ValueTraits::Factory());
    ASSERT_EQ(0, imm_empty.value());
    ASSERT_EQ(assm::kSizeNone, imm_empty.size());
    ASSERT_EQ(BasicBlockReference::REFERRED_TYPE_UNKNOWN,
              imm_empty.reference().referred_type());
  }

  Test8BitValue(0, 0);
  Test8BitValue(127, 127);

  Test8BitValue(static_cast<uint32_t>(-128), 0xFFFFFF80);
  Test8BitValue(0, 0);
  Test8BitValue(127, 0x0000007F);

  Test32BitValue(128, 0x00000080);
  Test32BitValue(0xCAFEBABE, 0xCAFEBABE);

  Test32BitValue(static_cast<uint32_t>(-129), 0xFFFFFF7F);
  Test32BitValue(128, 0x000000080);
  Test32BitValue(0xBABE, 0xBABE);

  {
    const BlockGraph::Offset kOffs = 10;
    auto imm_block_ref(ValueTraits::Factory(test_block_, kOffs));

    ASSERT_EQ(0, imm_block_ref.value());
    ASSERT_EQ(assm::kSize32Bit, imm_block_ref.size());
    ASSERT_EQ(BasicBlockReference::REFERRED_TYPE_BLOCK,
              imm_block_ref.reference().referred_type());
    ASSERT_EQ(test_block_, imm_block_ref.reference().block());
    ASSERT_EQ(kOffs, imm_block_ref.reference().offset());
    ASSERT_EQ(kOffs, imm_block_ref.reference().base());
  }

  {
    auto imm_bb_ref(ValueTraits::Factory(test_bb_));

    ASSERT_EQ(0, imm_bb_ref.value());
    ASSERT_EQ(assm::kSize32Bit, imm_bb_ref.size());
    ASSERT_EQ(BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK,
              imm_bb_ref.reference().referred_type());
    ASSERT_EQ(test_bb_, imm_bb_ref.reference().basic_block());
    ASSERT_EQ(0, imm_bb_ref.reference().offset());
    ASSERT_EQ(0, imm_bb_ref.reference().base());
  }

  {
    // Explicitly specified size and reference info.
    UntypedReference ref(test_block_, 1, 2);
    auto imm_expl_ref(ValueTraits::Factory(0xBE, assm::kSize8Bit, ref));

    ASSERT_EQ(0xBE, imm_expl_ref.value());
    ASSERT_EQ(assm::kSize8Bit, imm_expl_ref.size());
    ASSERT_EQ(BasicBlockReference::REFERRED_TYPE_BLOCK,
              imm_expl_ref.reference().referred_type());
    ASSERT_EQ(test_block_, imm_expl_ref.reference().block());
    ASSERT_EQ(1, imm_expl_ref.reference().offset());
    ASSERT_EQ(2, imm_expl_ref.reference().base());
  }
}

namespace {

// Asserts that @p op.displacement() is equal to @p displ.
void TestEqualDisplacement(const BasicBlockAssembler::Operand& op,
                           const BasicBlockAssembler::Displacement& displ) {
  ASSERT_EQ(displ.value(), op.displacement().value());
  ASSERT_EQ(displ.size(), op.displacement().size());

  ASSERT_EQ(displ.reference().IsValid(),
            op.displacement().reference().IsValid());
  if (!displ.reference().IsValid())
    return;

  ASSERT_EQ(displ.reference().IsValid(),
            op.displacement().reference().IsValid());

  ASSERT_EQ(displ.reference().basic_block(),
            op.displacement().reference().basic_block());
  ASSERT_EQ(displ.reference().block(),
            op.displacement().reference().block());
  ASSERT_EQ(displ.reference().offset(),
            op.displacement().reference().offset());
  ASSERT_EQ(displ.reference().base(),
            op.displacement().reference().base());
}

}  // namespace

typedef BasicBlockAssemblerTest OperandTest;

TEST_F(OperandTest, Factories) {
  {
    auto op(Operand(assm::eax));

    ASSERT_EQ(assm::kRegisterEax, op.base());
    ASSERT_EQ(assm::kRegisterNone, op.index());
    ASSERT_EQ(assm::kTimes1, op.scale());
    ASSERT_EQ(assm::kSizeNone, op.displacement().size());

    TestEqualDisplacement(op, Displacement());
  }

  {
    // Register-indirect with displacement.
    auto op(Operand(assm::eax, Displacement(100)));
    ASSERT_EQ(assm::kRegisterEax, op.base());
    ASSERT_EQ(assm::kRegisterNone, op.index());
    ASSERT_EQ(assm::kTimes1, op.scale());
    ASSERT_EQ(assm::kSize8Bit, op.displacement().size());

    TestEqualDisplacement(op, Displacement(100));

    TestEqualDisplacement(Operand(assm::eax, Displacement(test_block_, 2)),
                          Displacement(test_block_, 2));
    TestEqualDisplacement(Operand(assm::eax, Displacement(test_bb_)),
                          Displacement(test_bb_));
  }

  {
    // Displacement-only mode.
    auto op(Operand(Displacement(100)));
    ASSERT_EQ(assm::kRegisterNone, op.base());
    ASSERT_EQ(assm::kRegisterNone, op.index());
    ASSERT_EQ(assm::kTimes1, op.scale());
    ASSERT_EQ(assm::kSize8Bit, op.displacement().size());
    TestEqualDisplacement(op, Displacement(100));

    TestEqualDisplacement(Operand(Displacement(test_block_, 2)),
                          Displacement(test_block_, 2));
    TestEqualDisplacement(Operand(Displacement(test_bb_)),
                          Displacement(test_bb_));
  }

  {
    // The [base + index * scale] mode with displ.
    auto op(Operand(assm::eax, assm::ebp, assm::kTimes2, Displacement(100)));
    ASSERT_EQ(assm::kRegisterEax, op.base());
    ASSERT_EQ(assm::kRegisterEbp, op.index());
    ASSERT_EQ(assm::kTimes2, op.scale());
    ASSERT_EQ(assm::kSize8Bit, op.displacement().size());

    TestEqualDisplacement(
        Operand(assm::eax, assm::ebp, assm::kTimes2,
                Displacement(test_block_, 2)),
        Displacement(test_block_, 2));
    TestEqualDisplacement(
        Operand(assm::eax, assm::ebp, assm::kTimes2, Displacement(test_bb_)),
        Displacement(test_bb_));
  }

  {
    // The [base + index * scale] mode - no displ.
    auto op(Operand(assm::eax, assm::ebp, assm::kTimes2));
    ASSERT_EQ(assm::kRegisterEax, op.base());
    ASSERT_EQ(assm::kRegisterEbp, op.index());
    ASSERT_EQ(assm::kTimes2, op.scale());
    ASSERT_EQ(assm::kSizeNone, op.displacement().size());

    // The [index * scale + displ32] mode - no base.
    TestEqualDisplacement(Operand(assm::eax, assm::ebp, assm::kTimes2),
                          Displacement());
  }
}

TEST_F(BasicBlockAssemblerTest, nop) {
  // We can't use ASSERT_NO_REFS here as nop may generate more than 1
  // instruction, an exception to the rule of 1 instruction that ASSERT_NO_REFS
  // enforces.
  asm_.nop(0);
  ASSERT_EQ(0u, instructions_.size());

  // Exactly 1 or 2 instructions should be emitted per NOP length from
  // 1 to 15.
  for (size_t i = 1; i <= 15; ++i) {
    asm_.nop(i);
    ASSERT_LT(0u, instructions_.size());
    ASSERT_GE(2u, instructions_.size());

    // NOP instructions should have no references.
    for (BasicCodeBlock::Instructions::const_iterator inst_it =
             instructions_.begin();
         inst_it != instructions_.end();
         ++inst_it) {
      ASSERT_EQ(0u, inst_it->references().size());
    }
    instructions_.clear();
  }
}

TEST_F(BasicBlockAssemblerTest, call) {
  asm_.call(Immediate(test_block_, 0));
  ASSERT_REFS(1, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);

  asm_.call(Operand(Displacement(test_bb_)));
  ASSERT_REFS(2, BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK, test_bb_);
}

TEST_F(BasicBlockAssemblerTest, jmp) {
  asm_.jmp(Immediate(test_block_, 0));
  ASSERT_REFS(1, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);

  asm_.jmp(Operand(Displacement(test_bb_)));
  ASSERT_REFS(2, BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK, test_bb_);
}

TEST_F(BasicBlockAssemblerTest, mov_b) {
  // mov BYTE PTR [base + index * scale + displ], immediate
  asm_.mov_b(Operand(assm::eax, assm::ebx, assm::kTimes4,
                     Displacement(test_block_, 0)),
             Immediate(10));
  ASSERT_REFS(3, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);
}

TEST_F(BasicBlockAssemblerTest, movzx_b) {
  // movzx eax, BYTE PTR [base + index * scale + displ]
  asm_.movzx_b(assm::eax,
               Operand(assm::eax, assm::ebx, assm::kTimes4,
                       Displacement(test_block_, 0)));
  ASSERT_REFS(4, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);
}

TEST_F(BasicBlockAssemblerTest, mov) {
  // Simple register-register move.
  asm_.mov(assm::eax, assm::ebx);
  ASSERT_NO_REFS();

  // Simple immediate-register move.
  asm_.mov(assm::eax, Immediate(10));
  ASSERT_NO_REFS();

  // Immediate-with reference to register.
  asm_.mov(assm::eax, Immediate(test_block_, 0));
  ASSERT_REFS(1, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);

  // Torture test; mov [displ], immediate,
  // both src and dst contain references.
  asm_.mov(Operand(Displacement(test_block_, 0)), Immediate(test_bb_));
  ASSERT_REFS(2, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_,
              6, BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK, test_bb_);

  // Torture test; mov [base + index * scale + displ], immediate,
  // both src and dst contain references.
  asm_.mov(Operand(assm::eax, assm::ebx, assm::kTimes4,
                   Displacement(test_block_, 0)),
           Immediate(test_bb_));
  ASSERT_REFS(3, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_,
              7, BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK, test_bb_);
}

TEST_F(BasicBlockAssemblerTest, mov_fs) {
  asm_.mov_fs(Operand(assm::eax, assm::ebx, assm::kTimes4,
                      Displacement(test_block_, 0)),
              assm::eax);
  ASSERT_REFS(4, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);

  asm_.mov_fs(assm::eax,
              Operand(assm::eax, assm::ebx, assm::kTimes4,
                      Displacement(test_block_, 0)));
  ASSERT_REFS(4, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);
}

TEST_F(BasicBlockAssemblerTest, lea) {
  asm_.lea(assm::eax, Operand(assm::eax));
  ASSERT_NO_REFS();

  asm_.lea(assm::eax,
           Operand(assm::eax, assm::ebx, assm::kTimes4,
                   Displacement(test_bb_)));
  ASSERT_REFS(3, BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK, test_bb_);
}

TEST_F(BasicBlockAssemblerTest, push) {
  asm_.push(assm::esp);
  ASSERT_NO_REFS();

  asm_.push(Immediate(test_block_, 0));
  ASSERT_REFS(1, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);

  asm_.push(Operand(assm::eax, assm::ebx, assm::kTimes4,
                    Displacement(test_bb_)));
  ASSERT_REFS(3, BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK, test_bb_);
}

TEST_F(BasicBlockAssemblerTest, pop) {
  asm_.pop(assm::ebp);
  ASSERT_NO_REFS();

  asm_.pop(Operand(assm::eax, assm::ebx, assm::kTimes4,
                    Displacement(test_bb_)));
  ASSERT_REFS(3, BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK, test_bb_);
}

TEST_F(BasicBlockAssemblerTest, pushfd) {
  asm_.pushfd();
  ASSERT_NO_REFS();
}

TEST_F(BasicBlockAssemblerTest, popfd) {
  asm_.popfd();
  ASSERT_NO_REFS();
}

TEST_F(BasicBlockAssemblerTest, lahf) {
  asm_.lahf();
  ASSERT_NO_REFS();
}

TEST_F(BasicBlockAssemblerTest, sahf) {
  asm_.sahf();
  ASSERT_NO_REFS();
}

TEST_F(BasicBlockAssemblerTest, setxx) {
  // Simple register-register operation.
  asm_.set(assm::kParityEven, assm::eax);
  ASSERT_NO_REFS();

  asm_.set(assm::kOverflow, assm::ebx);
  ASSERT_NO_REFS();
}

TEST_F(BasicBlockAssemblerTest, test) {
  // Simple register-register operation.
  asm_.test(assm::al, assm::bl);
  ASSERT_NO_REFS();

  // Simple immediate-register operation.
  asm_.test(assm::al, Immediate(10, assm::kSize8Bit));
  ASSERT_NO_REFS();

  // Simple register-register operation.
  asm_.test(assm::eax, assm::ebx);
  ASSERT_NO_REFS();

  // Simple immediate-register operation.
  asm_.test(assm::eax, Immediate(10));
  ASSERT_NO_REFS();

  // Immediate-with reference to register.
  asm_.test(assm::eax, Immediate(test_block_, 0));
  ASSERT_REFS(1, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);

  // Torture test: both src and dst contain references.
  asm_.test(Operand(Displacement(test_block_, 0)), Immediate(test_bb_));
  ASSERT_REFS(2, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_,
              6, BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK, test_bb_);

  asm_.test(Operand(Displacement(test_block_, 0)), Immediate(10));
  ASSERT_REFS(2, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);
}

TEST_F(BasicBlockAssemblerTest, cmp) {
    // Simple register-register operation.
  asm_.cmp(assm::al, assm::bl);
  ASSERT_NO_REFS();

  // Simple immediate-register operation.
  asm_.cmp(assm::al, Immediate(10, assm::kSize8Bit));
  ASSERT_NO_REFS();

  // Simple register-register operation.
  asm_.cmp(assm::eax, assm::ebx);
  ASSERT_NO_REFS();

  // Simple immediate-register operation.
  asm_.cmp(assm::eax, Immediate(10));
  ASSERT_NO_REFS();

  // Immediate-with reference to register.
  asm_.cmp(assm::eax, Immediate(test_block_, 0));
  ASSERT_REFS(1, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);

  // Torture test: both src and dst contain references.
  asm_.cmp(Operand(Displacement(test_block_, 0)), Immediate(test_bb_));
  ASSERT_REFS(2, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_,
              6, BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK, test_bb_);

  asm_.cmp(Operand(Displacement(test_block_, 0)), Immediate(10));
  ASSERT_REFS(2, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);
}

TEST_F(BasicBlockAssemblerTest, add) {
  // Simple register-register operation.
  asm_.add(assm::al, assm::bl);
  ASSERT_NO_REFS();

  // Simple immediate-register operation.
  asm_.add(assm::al, Immediate(10, assm::kSize8Bit));
  ASSERT_NO_REFS();

  // Simple register-register operation.
  asm_.add(assm::eax, assm::ebx);
  ASSERT_NO_REFS();

  // Simple immediate-register operation.
  asm_.add(assm::eax, Immediate(10));
  ASSERT_NO_REFS();

  // Immediate-with reference to register.
  asm_.add(assm::eax, Immediate(test_block_, 0));
  ASSERT_REFS(1, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);

  // Torture test: both src and dst contain references.
  asm_.add(Operand(Displacement(test_block_, 0)), Immediate(test_bb_));
  ASSERT_REFS(2, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_,
              6, BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK, test_bb_);

  asm_.add(Operand(Displacement(test_block_, 0)), Immediate(10));
  ASSERT_REFS(2, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);
}

TEST_F(BasicBlockAssemblerTest, sub) {
  // Simple register-register operation.
  asm_.sub(assm::al, assm::bl);
  ASSERT_NO_REFS();

  // Simple immediate-register operation.
  asm_.sub(assm::al, Immediate(10, assm::kSize8Bit));
  ASSERT_NO_REFS();

  // Simple register-register operation.
  asm_.sub(assm::eax, assm::ebx);
  ASSERT_NO_REFS();

  // Simple immediate-register operation.
  asm_.sub(assm::eax, Immediate(10));
  ASSERT_NO_REFS();

  // Immediate-with reference to register.
  asm_.sub(assm::eax, Immediate(test_block_, 0));
  ASSERT_REFS(1, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);

  // Torture test: both src and dst contain references.
  asm_.sub(Operand(Displacement(test_block_, 0)), Immediate(test_bb_));
  ASSERT_REFS(2, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_,
              6, BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK, test_bb_);

  asm_.sub(Operand(Displacement(test_block_, 0)), Immediate(10));
  ASSERT_REFS(2, BasicBlockReference::REFERRED_TYPE_BLOCK, test_block_);
}

TEST_F(BasicBlockAssemblerTest, shl) {
  // Simple immediate-register operation.
  asm_.shl(assm::eax, Immediate(1));
  ASSERT_NO_REFS();
}

TEST_F(BasicBlockAssemblerTest, shr) {
  // Simple immediate-register operation.
  asm_.shr(assm::eax, Immediate(1));
  ASSERT_NO_REFS();
}

TEST_F(BasicBlockAssemblerTest, ret) {
  asm_.ret();
  ASSERT_NO_REFS();

  asm_.ret(4);
  ASSERT_NO_REFS();
}

TEST_F(BasicBlockAssemblerTest, xchg) {
  asm_.xchg(assm::eax, assm::ecx);
  ASSERT_NO_REFS();

  asm_.xchg(assm::esp, assm::edx);
  ASSERT_NO_REFS();

  asm_.xchg(assm::ax, assm::cx);
  ASSERT_NO_REFS();

  asm_.xchg(assm::sp, assm::dx);
  ASSERT_NO_REFS();

  asm_.xchg(assm::al, assm::ch);
  ASSERT_NO_REFS();

  asm_.xchg(assm::dh, assm::bl);
  ASSERT_NO_REFS();
}

TEST_F(BasicBlockAssemblerTest, UndefinedSourceRange) {
  ASSERT_EQ(asm_.source_range(), SourceRange());
  asm_.call(Immediate(test_block_, 0));
  ASSERT_EQ(instructions_.back().source_range(), SourceRange());
}

TEST_F(BasicBlockAssemblerTest, SetSourceRange) {
  SourceRange range(RelativeAddress(10), 10);
  asm_.set_source_range(range);
  asm_.call(Immediate(test_block_, 0));
  ASSERT_EQ(instructions_.back().source_range(), range);
}

TEST_F(BasicBlockAssemblerTest, SetMultipleSourceRange) {
  SourceRange range1(RelativeAddress(10), 10);
  SourceRange range2(RelativeAddress(20), 20);

  asm_.set_source_range(range1);
  asm_.call(Immediate(test_block_, 0));
  ASSERT_EQ(instructions_.back().source_range(), range1);

  asm_.set_source_range(range2);
  asm_.pop(assm::ebp);
  ASSERT_EQ(instructions_.back().source_range(), range2);

  asm_.ret(4);
  ASSERT_EQ(instructions_.back().source_range(), range2);
}

}  // namespace block_graph
