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

#include "syzygy/block_graph/unittest_util.h"

namespace testing {

namespace {

// TODO(chrisha): Break up the functions below into smaller reusable
//     components.

using block_graph::BlockGraph;
using block_graph::BlockGraphSerializer;

// Compare two strings to each others if the OMIT_STRINGS flag isn't set.
bool MaybeCompareStrings(const std::string& string1,
                         const std::string& string2,
                         const BlockGraphSerializer& bgs) {
  if (bgs.has_attributes(BlockGraphSerializer::OMIT_STRINGS)) {
    if (!string1.empty() && !string2.empty())
      return false;
    return true;
  }
  if (string1 != string2)
    return false;
  return true;
}

bool ReferencesEqual(const BlockGraph::Reference& ref1,
                     const BlockGraph::Reference& ref2) {
  if (ref1.base() != ref2.base() || ref1.offset() != ref2.offset() ||
      ref1.size() != ref2.size() || ref1.type() != ref2.type() ||
      ref1.referenced()->id() != ref2.referenced()->id()) {
    return false;
  }
  return true;
}

// Determines if the data in two blocks are equivalent, including the
// references. We do both at the same time so as to not check the actual data
// where references lie, which may be different post- and pre- image writing.
bool DataAndReferencesEqual(const BlockGraph::Block& b1,
                            const BlockGraph::Block& b2) {
  // The data and references need to be the same size.
  if (b1.data_size() != b2.data_size() ||
      b1.references().size() != b2.references().size()) {
    return false;
  }

  // Both data pointers should be null or non-null. We can't say anything
  // about data ownership, as this doesn't affect block equality.
  if ((b1.data() == NULL) != (b2.data() == NULL))
    return false;

  typedef BlockGraph::Block::ReferenceMap::const_iterator Iterator;
  Iterator it1 = b1.references().begin();
  Iterator it2 = b2.references().begin();
  Iterator end1 = b1.references().lower_bound(b1.data_size());

  const uint8* d1 = b1.data();
  const uint8* d2 = b2.data();
  BlockGraph::Offset i = 0;
  BlockGraph::Offset data_size = b1.data_size();

  // If either of the blocks don't have data, then the data-size should be 0.
  if (d1 == NULL || d2 == NULL)
    DCHECK_EQ(0, data_size);

  // Check the portion of data with embedded references.
  while (i < data_size && it1 != end1) {
    // Check the reference.
    if (it1->first != it2->first ||
        !ReferencesEqual(it1->second, it2->second)) {
      return false;
    }

    // Before the next reference? Then check the data is the same.
    if (i < it1->first) {
      if (::memcmp(d1 + i, d2 + i, it1->first - i) != 0)
        return false;
    }

    // Step past the reference.
    i = it1->first + it1->second.size();
    ++it1;
    ++it2;
  }

  // Check any remaining data.
  if (i < data_size && ::memcmp(d1 + i, d2 + i, data_size - i) != 0)
    return false;

  // Check the remaining references.
  end1 = b1.references().end();
  for (; it1 != end1; ++it1, ++it2) {
    if (it1->first != it2->first ||
        !ReferencesEqual(it1->second, it2->second)) {
      return false;
    }
  }

  return true;
}

bool ReferrersEqual(const BlockGraph::Block& b1,
                    const BlockGraph::Block& b2) {
  if (b1.referrers().size() != b2.referrers().size())
    return false;

  // Compare the referrers. They should point to blocks with the same id.
  // We store a list of unique referrer id/offset pairs. This allows us to
  // efficiently search for an equivalent referrer.
  typedef std::set<std::pair<size_t, size_t> > IdOffsetSet;
  IdOffsetSet id_offset_set;
  BlockGraph::Block::ReferrerSet::const_iterator it = b1.referrers().begin();
  for (; it != b1.referrers().end(); ++it)
    id_offset_set.insert(std::make_pair(it->first->id(), it->second));

  for (it = b2.referrers().begin(); it != b2.referrers().end(); ++it) {
    IdOffsetSet::const_iterator set_it = id_offset_set.find(
        std::make_pair(it->first->id(), it->second));
    if (set_it == id_offset_set.end())
      return false;
  }

  return true;
}

}  // namespace

// Compares two Blocks to each other.
bool BlocksEqual(const BlockGraph::Block& b1,
                 const BlockGraph::Block& b2,
                 const BlockGraphSerializer& bgs) {
  // Compare the basic block properties.
  if (b1.id() != b2.id() || b1.type() != b2.type() ||
      b1.size() != b2.size() || b1.alignment() != b2.alignment() ||
      b1.addr() != b2.addr() || b1.section() != b2.section() ||
      b1.attributes() != b2.attributes() ||
      b1.source_ranges() != b2.source_ranges() ||
      b1.data_size() != b2.data_size()) {
    return false;
  }

  if (!MaybeCompareStrings(b1.name(), b2.name(), bgs))
    return false;

  if (!MaybeCompareStrings(b1.compiland_name(), b2.compiland_name(), bgs))
    return false;

  // Compare the labels.
  if (!bgs.has_attributes(BlockGraphSerializer::OMIT_LABELS)) {
    if (b1.labels().size() != b2.labels().size())
      return false;
    BlockGraph::Block::LabelMap::const_iterator it1 =
        b1.labels().begin();
    BlockGraph::Block::LabelMap::const_iterator it2 =
        b2.labels().begin();
    for (; it1 != b1.labels().end(); ++it1, ++it2) {
      if (it1->first != it2->first ||
          it1->second.attributes() != it2->second.attributes() ||
          !MaybeCompareStrings(it1->second.name(),
                               it2->second.name(),
                               bgs)) {
        return false;
      }
    }
  }

  // Compare the data and the references.
  if (!DataAndReferencesEqual(b1, b2))
    return false;

  // Compare the referrers.
  if (!ReferrersEqual(b1, b2))
    return false;

  return true;
}

// Compares two BlockGraphs to each other.
bool BlockGraphsEqual(const BlockGraph& b1,
                      const BlockGraph& b2,
                      const BlockGraphSerializer& bgs) {
  if (b1.sections() != b2.sections() ||
      b1.blocks().size() != b2.blocks().size()) {
    return false;
  }

  // We manually iterate through the blocks and use BlocksEqual,
  // because they don't otherwise have a comparison operator.
  BlockGraph::BlockMap::const_iterator it1 = b1.blocks().begin();
  for (; it1 != b1.blocks().end(); ++it1) {
    BlockGraph::BlockMap::const_iterator it2 = b2.blocks().find(it1->first);
    if (it2 == b2.blocks().end())
      return false;

    if (!BlocksEqual(it1->second, it2->second, bgs))
      return false;
  }

  return true;
}

bool GenerateTestBlockGraph(block_graph::BlockGraph* image) {
  DCHECK(image != NULL);

  BlockGraph::Section* s1 = image->AddSection("s1", 0);
  BlockGraph::Section* s2 = image->AddSection("s2", 0);
  if (s1 == NULL || s2 == NULL)
    return false;

  BlockGraph::Block* b1 = image->AddBlock(BlockGraph::CODE_BLOCK, 0x20, "b1");
  BlockGraph::Block* b2 = image->AddBlock(BlockGraph::CODE_BLOCK, 0x20, "b2");
  BlockGraph::Block* b3 = image->AddBlock(BlockGraph::CODE_BLOCK, 0x20, "b3");
  if (b1 == NULL || b2 == NULL || b3 == NULL)
    return false;

  b1->set_section(s1->id());
  b2->set_section(s1->id());
  b3->set_section(s2->id());
  if (b1->section() != s1->id() ||
      b2->section() != s1->id() ||
      b3->section() != s2->id())
      return false;

  b1->SetLabel(0x04, "label1", BlockGraph::CODE_LABEL);
  b2->SetLabel(0x08, "label2", BlockGraph::DATA_LABEL);
  b3->SetLabel(0x0C, "label3", BlockGraph::CODE_LABEL);
  b3->SetLabel(0x10, "label4", BlockGraph::DATA_LABEL);

  uint8* b1_data = b1->AllocateData(b1->size());
  for (size_t i = 0; i < b1->size(); ++i) {
    b1_data[i] = 0;
  }

  if (!b1->references().empty() ||
      !b1->referrers().empty() ||
      !b2->references().empty() ||
      !b2->referrers().empty() ||
      !b3->references().empty() ||
      !b3->referrers().empty())
     return false;

  BlockGraph::Reference r_pc(BlockGraph::PC_RELATIVE_REF, 1, b2, 9, 9);
  if (!b1->SetReference(0, r_pc) || !b1->SetReference(1, r_pc))
    return false;

  BlockGraph::Reference r_abs(BlockGraph::ABSOLUTE_REF, 4, b2, 13, 13);
  if (b1->SetReference(1, r_abs))
    return false;

  BlockGraph::Reference r_rel(BlockGraph::RELATIVE_REF, 4, b2, 17, 17);
  if (!b1->SetReference(5, r_rel))
    return false;

  BlockGraph::Reference r_file(BlockGraph::FILE_OFFSET_REF, 4, b2, 23, 23);
  if (!b1->SetReference(9, r_file))
    return false;

  return true;
}

bool DummyTransformPolicy::BlockIsSafeToBasicBlockDecompose(
    const BlockGraph::Block* block) const {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);
  if (block->type() != BlockGraph::CODE_BLOCK)
    return false;
  return true;
}

bool DummyTransformPolicy::ReferenceIsSafeToRedirect(
    const BlockGraph::Block* referrer,
    const BlockGraph::Reference& reference) const {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), referrer);
  return true;
}

}  // namespace testing
