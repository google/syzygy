// Copyright 2011 Google Inc.
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
#include "syzygy/core/typed_block.h"
#include "gtest/gtest.h"

namespace core {

class TypedBlockTest: public testing::Test {
 public:
  virtual void SetUp() {
    foo_.reset(new BlockGraph::Block(
        0, BlockGraph::DATA_BLOCK, sizeof(Foo), "foo"));
    bar_.reset(new BlockGraph::Block(
        0, BlockGraph::DATA_BLOCK, sizeof(Bar), "bar"));
    foo_const_ = foo_.get();

    ASSERT_TRUE(foo_->AllocateData(sizeof(Foo)) != NULL);
    ASSERT_TRUE(bar_->AllocateData(sizeof(Bar)) != NULL);

    // Create a connection between the two blocks.
    ASSERT_TRUE(foo_->SetReference(
        offsetof(Foo, bar),
        BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                              4,
                              bar_.get(),
                              0)));
  }

 protected:
  struct Bar {
    int i;
    double d[5];
  };

  struct Foo {
    float f;
    Bar* bar;
  };

  static void CompileAsserts() {
    COMPILE_ASSERT(sizeof(Bar) > sizeof(Foo), Bar_must_be_bigger_than_Foo);
  }

  scoped_ptr<BlockGraph::Block> foo_;
  scoped_ptr<BlockGraph::Block> bar_;
  const BlockGraph::Block* foo_const_;
};

TEST_F(TypedBlockTest, Init) {
  TypedBlock<Foo> foo;

  // This should fail as foo is not big enough to house a Foo at offset 1.
  EXPECT_FALSE(foo.IsValid());
  EXPECT_FALSE(foo.Init(1, foo_.get()));
  EXPECT_FALSE(foo.IsValid());

  // This should work fine.
  EXPECT_TRUE(foo.Init(0, foo_.get()));
  EXPECT_TRUE(foo.IsValid());
  EXPECT_EQ(foo.block(), foo_.get());
  EXPECT_EQ(foo.offset(), 0);

  // This should also work fine.
  ConstTypedBlock<Foo> foo_const;
  EXPECT_TRUE(foo_const.Init(0, foo_.get()));
  EXPECT_TRUE(foo_const.IsValid());

  // This should fail as bar is bigger than foo.
  TypedBlock<Bar> bar;
  EXPECT_FALSE(bar.IsValid());
  EXPECT_FALSE(bar.Init(0, foo_.get()));
}

TEST_F(TypedBlockTest, Access) {
  TypedBlock<Foo> foo;
  ASSERT_TRUE(foo.Init(0, foo_.get()));

  const Foo* foo_direct = reinterpret_cast<const Foo*>(foo_->data());
  EXPECT_EQ(foo_direct, foo.Get());
  EXPECT_EQ(foo_direct, &(*foo));

  foo->f = 4.5;
  EXPECT_EQ(4.5, foo_direct->f);
}

TEST_F(TypedBlockTest, Dereference) {
  TypedBlock<Foo> foo;
  ASSERT_TRUE(foo.Init(0, foo_.get()));

  TypedBlock<Bar> bar;
  EXPECT_TRUE(foo.Dereference(foo->bar, &bar));
  ASSERT_TRUE(bar.IsValid());

  EXPECT_TRUE(foo.DereferenceAt(offsetof(Foo, bar), &bar));
  ASSERT_TRUE(bar.IsValid());

  bar->i = 42;
  EXPECT_EQ(42, reinterpret_cast<const Bar*>(bar_->data())->i);
}

}  // namespace core
