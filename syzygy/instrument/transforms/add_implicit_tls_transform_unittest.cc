// Copyright 2017 Google Inc. All Rights Reserved.
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

#include "syzygy/instrument/transforms/add_implicit_tls_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {
namespace transforms {

typedef block_graph::BlockGraph BlockGraph;

namespace {

class AddImplicitTlsTransformTest : public testing::TestDllTransformTest {};

}  // namespace

TEST_F(AddImplicitTlsTransformTest, ApplyImplicitTlsTranformAppend) {
  struct cov {
    uint8_t padd[10];
    uint32_t unused;
    uint32_t here;
    uint32_t nothere;
  };

  BlockGraph::Block* data_block =
      block_graph_.AddBlock(BlockGraph::DATA_BLOCK, sizeof(cov), "cov");

  AddImplicitTlsTransform add_implicit_tls(data_block, offsetof(cov, here));

  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  const BlockGraph::BlockMap& blocks = block_graph_.blocks();
  const BlockGraph::Block* tls_used = nullptr;

  for (const auto& block : blocks) {
    std::string name(block.second.name());
    if (name == AddImplicitTlsTransform::kTlsUsed) {
      tls_used = &block.second;
      break;
    }
  }

  ASSERT_NE(tls_used, nullptr);

  BlockGraph::Reference tls_start_ref;
  ASSERT_TRUE(tls_used->GetReference(
      offsetof(IMAGE_TLS_DIRECTORY, StartAddressOfRawData), &tls_start_ref));

  BlockGraph::Reference tls_end_ref;
  ASSERT_TRUE(tls_used->GetReference(
      offsetof(IMAGE_TLS_DIRECTORY, EndAddressOfRawData), &tls_end_ref));

  size_t tls_start_offset_origin = tls_start_ref.offset();
  size_t tls_end_offset_origin = tls_end_ref.offset();

  const BlockGraph::Block* tls_start = tls_start_ref.referenced();
  size_t size_before_appending = tls_start->size();

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &add_implicit_tls, policy_, &block_graph_, header_block_));

  // The tls section is already pretty full, hence the big offset below.
  EXPECT_EQ(add_implicit_tls.tls_displacement(), 792);

  // One should be __tls_used (that is the block containing _tls_index),
  // and the other one should be DllMain.
  // The second referrer is coming from the usage of one of the implicit TLS
  // slot defined.
  // Below is the disassembly of DllMain accessing 'tls_double' variable (offset
  // +0x10):
  //   .text:10001516 | mov     eax, large fs:2Ch
  //   .text:1000151C | mov     ecx, __tls_index <- here
  //   .text:10001522 | mov     ecx, [eax+ecx*4]
  //   .text:10001525 | cvttsd2si edx, qword ptr [ecx+10h]
  //   ...
  //   .tls:1001C000 __tls_start     db    0
  //   [...]
  //   .tls:1001C010 ; double tls_double <- the variable accessed
  // In the debug test_dll.dll, there are more references because I'm guessing
  // that the compiler doesn't optimize a bunch of accesses, and will reference
  // __tls_index every time, so using >=.
  EXPECT_LE(2, data_block->referrers().size());

  const auto& referrers = data_block->referrers();
  const BlockGraph::Block* tls_used_referrer = nullptr;
  for (const auto& referrer : referrers) {
    std::string name(referrer.first->name());
    if (name == AddImplicitTlsTransform::kTlsUsed) {
      tls_used_referrer = referrer.first;
      break;
    }
  }

  // Ensure the two __tls_used block pointers we obtained by two different ways,
  // are the same.
  ASSERT_NE(tls_used_referrer, nullptr);
  ASSERT_EQ(tls_used_referrer, tls_used);

  // We get a reference to __tls_index to check in which block and at what
  // offset it's pointing to.
  BlockGraph::Reference tls_index_ref;
  ASSERT_TRUE(tls_used->GetReference(
      offsetof(IMAGE_TLS_DIRECTORY, AddressOfIndex), &tls_index_ref));

  BlockGraph::Block* tls_index = tls_index_ref.referenced();
  ASSERT_EQ(tls_index, data_block);
  ASSERT_EQ(tls_index_ref.offset(), offsetof(cov, here));

  // We make sure that we extended the block size for our slot.
  ASSERT_EQ(size_before_appending + sizeof(uint32_t), tls_start->size());

  // Update the reference pointers.
  ASSERT_TRUE(tls_used->GetReference(
      offsetof(IMAGE_TLS_DIRECTORY, StartAddressOfRawData), &tls_start_ref));

  ASSERT_TRUE(tls_used->GetReference(
      offsetof(IMAGE_TLS_DIRECTORY, EndAddressOfRawData), &tls_end_ref));

  // We make sure the offset of __tls_start didn't change since the beginning.
  ASSERT_EQ(tls_start_offset_origin, tls_start_ref.offset());

  // We make sure that the offset of __tls_end did change.
  ASSERT_EQ(tls_end_offset_origin + sizeof(uint32_t), tls_end_ref.offset());

  // Make sure that the displacement value is what the layout really is.
  EXPECT_EQ(add_implicit_tls.tls_displacement(),
            tls_end_ref.offset() - sizeof(uint32_t));
}

TEST_F(AddImplicitTlsTransformTest, ApplyImplicitTlsTranformCreate) {
  size_t offset = 0;
  BlockGraph::Block* data_block =
      block_graph_.AddBlock(BlockGraph::DATA_BLOCK, sizeof(uint32_t), "cov");

  AddImplicitTlsTransform add_implicit_tls(data_block, offset);

  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  // One way to exercise the 'creation' path, is by modifying the name of
  // the _tls_index variable. This tricks the code into thinking no slots exist.
  BlockGraph::BlockMap& blocks = block_graph_.blocks_mutable();
  for (auto& block : blocks) {
    std::string name(block.second.name());
    if (name == AddImplicitTlsTransform::kTlsIndex) {
      block.second.set_name(":)");
      break;
    }
  }

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &add_implicit_tls, policy_, &block_graph_, header_block_));

  // We are creating the section this time and we know the offset should be +4.
  EXPECT_EQ(add_implicit_tls.tls_displacement(), 4);

  // The only referrer should be __tls_used (that is the block containing
  // _tls_index).
  EXPECT_EQ(1, data_block->referrers().size());
  const auto& referrers = data_block->referrers();
  BlockGraph::Block* tls_used = referrers.begin()->first;
  ASSERT_EQ(tls_used->name(), AddImplicitTlsTransform::kTlsUsed);

  // We get a reference to __tls_index to check in which block and at what
  // offset it's pointing to.
  BlockGraph::Reference tls_index_ref;
  ASSERT_TRUE(tls_used->GetReference(
      offsetof(IMAGE_TLS_DIRECTORY, AddressOfIndex), &tls_index_ref));

  BlockGraph::Block* tls_index = tls_index_ref.referenced();
  ASSERT_EQ(tls_index, data_block);
  ASSERT_EQ(tls_index_ref.offset(), offset);
}

}  // namespace transforms
}  // namespace instrument
