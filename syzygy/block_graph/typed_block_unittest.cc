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

#include "syzygy/block_graph/typed_block.h"

#include "gtest/gtest.h"

namespace block_graph {

class TypedBlockTest: public testing::Test {
 public:
  virtual void SetUp() {
    foo_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK, sizeof(Foo), "foo");

    bar_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK,
                                 sizeof(Bar) + 4,
                                 "bar");
    foo_const_ = foo_;

    ASSERT_TRUE(foo_->AllocateData(foo_->size()) != NULL);
    ASSERT_TRUE(bar_->AllocateData(bar_->size()) != NULL);

    // Create a connection between the two blocks.
    ASSERT_TRUE(foo_->SetReference(
        offsetof(Foo, bar),
        BlockGraph::Reference(BlockGraph::RELATIVE_REF, 4, bar_, 0, 0)));

    // Create an indirect reference between the two blocks. indirect_d is
    // a 1-indexed array pointing to Bar::d.
    BlockGraph::Offset d_base = offsetof(Bar, d);
    BlockGraph::Offset d_offset = d_base - sizeof(double);
    ASSERT_TRUE(foo_->SetReference(
        offsetof(Foo, indirect_d),
        BlockGraph::Reference(BlockGraph::RELATIVE_REF, 4, bar_,
        d_offset, d_base)));
  }

 protected:
  struct Bar {
    int i;
    double d[5];
  };

  struct Foo {
    float f;
    Bar* bar;
    double* indirect_d;
  };

  static void CompileAsserts() {
    static_assert(sizeof(Bar) > sizeof(Foo), "Bar must be bigger than foo.");
  }

  BlockGraph block_graph_;
  BlockGraph::Block* foo_;
  BlockGraph::Block* bar_;
  const BlockGraph::Block* foo_const_;
};

TEST_F(TypedBlockTest, Init) {
  TypedBlock<Foo> foo;

  // This should fail as foo is not big enough to house a Foo at offset 1.
  EXPECT_FALSE(foo.IsValid());
  EXPECT_FALSE(foo.Init(1, foo_));
  EXPECT_FALSE(foo.IsValid());

  // This should work fine.
  EXPECT_TRUE(foo.Init(0, foo_));
  EXPECT_TRUE(foo.IsValid());
  EXPECT_EQ(foo.block(), foo_);
  EXPECT_EQ(foo.offset(), 0);
  EXPECT_EQ(foo.size(), sizeof(Foo));

  // This should also work fine.
  ConstTypedBlock<Foo> foo_const;
  EXPECT_TRUE(foo_const.Init(0, foo_));
  EXPECT_TRUE(foo_const.IsValid());
  EXPECT_EQ(foo.block(), foo_);
  EXPECT_EQ(foo.offset(), 0);
  EXPECT_EQ(foo.size(), sizeof(Foo));

  // This should fail as bar is bigger than foo.
  TypedBlock<Bar> bar;
  EXPECT_FALSE(bar.IsValid());
  EXPECT_FALSE(bar.Init(0, foo_));
}

TEST_F(TypedBlockTest, InitWithSize) {
  TypedBlock<Foo> foo;

  // This should fail as foo is not big enough to house a Foo at offset 1.
  EXPECT_FALSE(foo.IsValid());
  EXPECT_FALSE(foo.InitWithSize(1, sizeof(Foo), foo_));
  EXPECT_FALSE(foo.IsValid());

  // This should fail as foo is not big enough to house two Foo's.
  EXPECT_FALSE(foo.IsValid());
  EXPECT_FALSE(foo.InitWithSize(0, 2 * sizeof(Foo), foo_));
  EXPECT_FALSE(foo.IsValid());

  // This should work fine.
  EXPECT_TRUE(foo.InitWithSize(0, sizeof(Foo), foo_));
  EXPECT_TRUE(foo.IsValid());
  EXPECT_EQ(foo.block(), foo_);
  EXPECT_EQ(foo.offset(), 0);
  EXPECT_EQ(foo.size(), sizeof(Foo));

  // This should also work fine.
  ConstTypedBlock<Foo> foo_const;
  EXPECT_TRUE(foo_const.InitWithSize(0, sizeof(Foo), foo_));
  EXPECT_TRUE(foo_const.IsValid());

  TypedBlock<Bar> bar;
  EXPECT_TRUE(bar.InitWithSize(0, sizeof(Bar) + 4, bar_));
  EXPECT_EQ(sizeof(Bar) + 4, bar.size());
}

TEST_F(TypedBlockTest, IsValidElement) {
  TypedBlock<Foo> foo;
  ASSERT_TRUE(foo.Init(0, foo_));
  ASSERT_TRUE(foo.IsValidElement(0));
  ASSERT_FALSE(foo.IsValidElement(1));

  foo_->ResizeData(2 * sizeof(Foo));
  ASSERT_TRUE(foo.InitWithSize(0, foo_->size(), foo_));
  ASSERT_TRUE(foo.IsValidElement(0));
  ASSERT_TRUE(foo.IsValidElement(1));
}

TEST_F(TypedBlockTest, ElementCount) {
  TypedBlock<int> ints;
  BlockGraph block_graph;
  BlockGraph::Block* ints_block =
      block_graph.AddBlock(BlockGraph::DATA_BLOCK, 10 * sizeof(int), "ints");
  ints_block->AllocateData(ints_block->size());

  ASSERT_TRUE(ints.Init(0, ints_block));
  EXPECT_EQ(10u, ints.ElementCount());

  ASSERT_TRUE(ints.Init(4 * sizeof(int), ints_block));
  EXPECT_EQ(6u, ints.ElementCount());
}

TEST_F(TypedBlockTest, Access) {
  TypedBlock<Foo> foo;
  ASSERT_TRUE(foo.Init(0, foo_));

  const Foo* foo_direct = reinterpret_cast<const Foo*>(foo_->data());
  EXPECT_EQ(1u, foo.ElementCount());
  EXPECT_EQ(foo_direct, foo.Get());
  EXPECT_EQ(foo_direct, &(*foo));
  EXPECT_EQ(foo_direct, &foo[0]);

  foo->f = 4.5f;
  EXPECT_EQ(4.5f, foo_direct->f);

  foo[0].f = 5.4f;
  EXPECT_EQ(5.4f, foo_direct->f);
}

TEST_F(TypedBlockTest, OffsetOf) {
  TypedBlock<Foo> foo;
  ASSERT_TRUE(foo.Init(0, foo_));

  EXPECT_EQ(offsetof(Foo, bar), foo.OffsetOf(foo->bar));

  ASSERT_TRUE(foo.Init(2, bar_));
  EXPECT_EQ(offsetof(Foo, bar) + 2, foo.OffsetOf(foo->bar));
}

TEST_F(TypedBlockTest, HasReference) {
  TypedBlock<Foo> foo;
  ASSERT_TRUE(foo.Init(0, foo_));

  EXPECT_TRUE(foo.HasReferenceAt(offsetof(Foo, bar)));
  EXPECT_TRUE(foo.HasReferenceAt(offsetof(Foo, bar), sizeof(foo->bar)));
  EXPECT_TRUE(foo.HasReference(foo->bar));

  EXPECT_FALSE(foo.HasReferenceAt(offsetof(Foo, bar) + 1));
  EXPECT_FALSE(foo.HasReferenceAt(offsetof(Foo, bar), 1));
  EXPECT_FALSE(foo.HasReference(foo->f));
}

TEST_F(TypedBlockTest, Dereference) {
  TypedBlock<Foo> foo;
  ASSERT_TRUE(foo.Init(0, foo_));

  TypedBlock<Bar> bar;
  EXPECT_TRUE(foo.Dereference(foo->bar, &bar));
  ASSERT_TRUE(bar.IsValid());

  EXPECT_TRUE(foo.DereferenceAt(offsetof(Foo, bar), &bar));
  ASSERT_TRUE(bar.IsValid());

  bar->i = 42;
  EXPECT_EQ(42, reinterpret_cast<const Bar*>(bar_->data())->i);
}

TEST_F(TypedBlockTest, DereferenceWithSize) {
  TypedBlock<Foo> foo;
  ASSERT_TRUE(foo.Init(0, foo_));

  TypedBlock<Bar> bar;
  EXPECT_TRUE(foo.DereferenceWithSize(foo->bar, sizeof(Bar) + 4, &bar));
  ASSERT_TRUE(bar.IsValid());
  EXPECT_EQ(sizeof(Bar) + 4, bar.size());

  EXPECT_TRUE(foo.DereferenceAtWithSize(offsetof(Foo, bar), sizeof(Bar) + 4,
                                        &bar));
  ASSERT_TRUE(bar.IsValid());
  EXPECT_EQ(sizeof(Bar) + 4, bar.size());

  bar->i = 42;
  EXPECT_EQ(42, reinterpret_cast<const Bar*>(bar_->data())->i);
}

TEST_F(TypedBlockTest, IndirectDereferenceFails) {
  TypedBlock<Foo> foo;
  ASSERT_TRUE(foo.Init(0, foo_));

  TypedBlock<double> d;
  EXPECT_FALSE(foo.Dereference(foo->indirect_d, &d));
  EXPECT_FALSE(foo.DereferenceAt(offsetof(Foo, indirect_d), &d));
  EXPECT_FALSE(foo.DereferenceWithSize(foo->indirect_d, 4, &d));
  EXPECT_FALSE(foo.DereferenceAtWithSize(offsetof(Foo, indirect_d), 4, &d));
}

TEST_F(TypedBlockTest, RemoveReferenceAt) {
  TypedBlock<Foo> foo;
  ASSERT_TRUE(foo.Init(0, foo_));
  foo.RemoveReferenceAt(offsetof(Foo, bar));
  EXPECT_FALSE(foo.HasReferenceAt(offsetof(Foo, bar)));
}

TEST_F(TypedBlockTest, RemoveReferenceAtWithSize) {
  TypedBlock<Foo> foo;
  ASSERT_TRUE(foo.Init(0, foo_));
  EXPECT_TRUE(foo.RemoveReferenceAt(offsetof(Foo, bar), sizeof(foo->bar)));
  EXPECT_FALSE(foo.HasReferenceAt(offsetof(Foo, bar)));
}

TEST_F(TypedBlockTest, RemoveReferenceAtWithSizeFails) {
  TypedBlock<Foo> foo;
  ASSERT_TRUE(foo.Init(0, foo_));
  EXPECT_FALSE(foo.RemoveReferenceAt(offsetof(Foo, bar), 1));
  EXPECT_TRUE(foo.HasReferenceAt(offsetof(Foo, bar)));
}

TEST_F(TypedBlockTest, RemoveReferenceByValue) {
  TypedBlock<Foo> foo;
  ASSERT_TRUE(foo.Init(0, foo_));
  EXPECT_TRUE(foo.RemoveReference(foo->bar));
  EXPECT_FALSE(foo.HasReferenceAt(offsetof(Foo, bar)));
}

TEST_F(TypedBlockTest, SetReference) {
  TypedBlock<Foo> foo;
  TypedBlock<Bar> bar;
  ASSERT_TRUE(foo.Init(0, foo_));
  ASSERT_TRUE(foo.Dereference(foo->bar, &bar));

  TypedBlock<Bar> bar2;

  ASSERT_TRUE(foo.RemoveReference(foo->bar));

  EXPECT_TRUE(foo.SetReference(BlockGraph::RELATIVE_REF,
                               offsetof(Foo, bar),
                               sizeof(foo->bar),
                               bar.block(),
                               bar.offset(),
                               bar.offset()));
  EXPECT_TRUE(foo.Dereference(foo->bar, &bar2));
  EXPECT_EQ(bar.block(), bar2.block());
  EXPECT_EQ(bar.offset(), bar2.offset());

  ASSERT_TRUE(foo.RemoveReference(foo->bar));

  EXPECT_TRUE(foo.SetReference(BlockGraph::RELATIVE_REF,
                               foo->bar,
                               bar.block(),
                               bar.offset(),
                               bar.offset()));
  EXPECT_TRUE(foo.Dereference(foo->bar, &bar2));
  EXPECT_EQ(bar.block(), bar2.block());
  EXPECT_EQ(bar.offset(), bar2.offset());

  ASSERT_TRUE(foo.RemoveReference(foo->bar));

  EXPECT_TRUE(foo.SetReference(BlockGraph::RELATIVE_REF,
                               foo->bar,
                               bar));
  EXPECT_TRUE(foo.Dereference(foo->bar, &bar2));
  EXPECT_EQ(bar.block(), bar2.block());
  EXPECT_EQ(bar.offset(), bar2.offset());

  ASSERT_TRUE(foo.RemoveReference(foo->bar));

  EXPECT_TRUE(foo.SetReference(BlockGraph::RELATIVE_REF,
                               foo->bar,
                               bar,
                               bar->i));
  EXPECT_TRUE(foo.Dereference(foo->bar, &bar2));
  EXPECT_EQ(bar.block(), bar2.block());
  EXPECT_EQ(bar.offset(), bar2.offset());
}

}  // namespace block_graph
