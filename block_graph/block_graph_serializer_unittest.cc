// Copyright 2012 Google Inc.
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

#include "syzygy/block_graph/block_graph_serializer.h"

#include "gtest/gtest.h"
#include "syzygy/core/serialization.h"

namespace block_graph {

TEST(BlockGraphSerializerTest, Construction) {
  BlockGraphSerializer s;
  ASSERT_EQ(BlockGraphSerializer::DEFAULT_DATA_MODE, s.data_mode());
  ASSERT_EQ(BlockGraphSerializer::DEFAULT_ATTRIBUTES, s.data_mode());
}

TEST(BlockGraphSerializerTest, SetDataMode) {
  BlockGraphSerializer s;
  ASSERT_EQ(BlockGraphSerializer::DEFAULT_DATA_MODE, s.data_mode());

  s.set_data_mode(BlockGraphSerializer::OUTPUT_NO_DATA);
  ASSERT_EQ(BlockGraphSerializer::OUTPUT_NO_DATA, s.data_mode());

  s.set_data_mode(BlockGraphSerializer::OUTPUT_ALL_DATA);
  ASSERT_EQ(BlockGraphSerializer::OUTPUT_ALL_DATA, s.data_mode());
}

TEST(BlockGraphSerializerTest, AddAttributes) {
  BlockGraphSerializer s;
  ASSERT_EQ(0u, s.attributes());

  s.add_attributes(1);
  ASSERT_EQ(1u, s.attributes());

  s.add_attributes(2 | 4);
  ASSERT_EQ(1u | 2u | 4u, s.attributes());
}

TEST(BlockGraphSerializerTest, ClearAttributes) {
  BlockGraphSerializer s;
  ASSERT_EQ(0u, s.attributes());

  s.add_attributes(1 | 2);
  ASSERT_EQ(1u | 2u, s.attributes());

  s.clear_attributes(2);
  ASSERT_EQ(1u, s.attributes());
}

TEST(BlockGraphSerializerTest, SetAttributes) {
  BlockGraphSerializer s;
  ASSERT_EQ(0u, s.attributes());

  s.set_attributes(1 | 2);
  ASSERT_EQ(1u | 2u, s.attributes());

  s.set_attributes(4 | 8);
  ASSERT_EQ(4u | 8u, s.attributes());
}

TEST(BlockGraphSerializerTest, HasAttributes) {
  BlockGraphSerializer s;
  ASSERT_EQ(0u, s.attributes());

  s.set_attributes(1 | 2);
  ASSERT_EQ(1u | 2u, s.attributes());

  ASSERT_TRUE(s.has_attributes(1));
  ASSERT_TRUE(s.has_attributes(2));
  ASSERT_TRUE(s.has_attributes(1 | 2));
  ASSERT_FALSE(s.has_attributes(1 | 2 | 4));
}

TEST(BlockGraphSerializerTest, HasAnyAttributes) {
  BlockGraphSerializer s;
  ASSERT_EQ(0u, s.attributes());

  s.set_attributes(1 | 2);
  ASSERT_EQ(1u | 2u, s.attributes());

  ASSERT_TRUE(s.has_any_attributes(1));
  ASSERT_TRUE(s.has_any_attributes(2));
  ASSERT_TRUE(s.has_any_attributes(1 | 2 | 4));
  ASSERT_FALSE(s.has_any_attributes(4 | 8));
}

TEST(BlockGraphSerializerTest, Save) {
  BlockGraphSerializer s;
  BlockGraph bg;

  std::vector<uint8> v;
  scoped_ptr<core::OutStream> os(
      core::CreateByteOutStream(std::back_inserter(v)));
  core::NativeBinaryOutArchive oa(os.get());
  ASSERT_FALSE(s.Save(bg, &oa));
  ASSERT_EQ(0u, v.size());
}

TEST(BlockGraphSerializerTest, Load) {
  BlockGraphSerializer s;
  BlockGraph bg;

  std::vector<uint8> v;
  scoped_ptr<core::InStream> is(
      core::CreateByteInStream(v.begin(), v.end()));
  core::NativeBinaryInArchive ia(is.get());
  ASSERT_FALSE(s.Load(&bg, &ia));
  ASSERT_EQ(0u, bg.blocks().size());
}

}  // namespace block_graph
