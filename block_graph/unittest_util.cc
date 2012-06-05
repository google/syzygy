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

#include "syzygy/block_graph/unittest_util.h"

namespace testing {

using block_graph::BlockGraph;

// Compare two strings to each others if the OMIT_STRINGS flag isn't set.
bool MaybeCompareString(const std::string string1,
                        const std::string string2,
                        BlockGraph::SerializationAttributes attributes) {
  if ((attributes & BlockGraph::OMIT_STRINGS) == 0) {
    if (string1 != string2)
      return false;
  }
  return true;
}

// Compares two Blocks to each other.
bool BlocksEqual(const BlockGraph::Block& b1,
                 const BlockGraph::Block& b2,
                 BlockGraph::SerializationAttributes attributes) {
  // Compare the basic block properties.
  if (b1.id() != b2.id() || b1.type() != b2.type() ||
      b1.size() != b2.size() || b1.alignment() != b2.alignment() ||
      b1.addr() != b2.addr() || b1.section() != b2.section() ||
      b1.attributes() != b2.attributes() ||
      b1.source_ranges() != b2.source_ranges() ||
      b1.data_size() != b2.data_size()) {
    return false;
  }

  if (!MaybeCompareString(b1.name(), b2.name(), attributes))
    return false;

  // Compare the labels.
  if ((attributes & BlockGraph::OMIT_LABELS) == 0) {
    if (b1.labels().size() != b2.labels().size())
      return false;
    BlockGraph::Block::LabelMap::const_iterator label1_iter =
        b1.labels().begin();
    BlockGraph::Block::LabelMap::const_iterator label2_iter =
        b1.labels().begin();
    for (; label1_iter != b1.labels().end(); label1_iter++, label2_iter++) {
      if (label1_iter->first != label2_iter->first ||
          label1_iter->second.type() != label2_iter->second.type() ||
          !MaybeCompareString(label1_iter->second.name(),
                              label2_iter->second.name(),
                              attributes)) {
        return false;
      }
    }
  }

  if ((attributes & BlockGraph::OMIT_DATA) == 0) {
    // Both data pointers should be null or non-null.
    if ((b1.data() == NULL) != (b2.data() == NULL) ||
        b1.owns_data() != b2.owns_data())
      return false;

    // Compare the data.
    if (b1.data_size() > 0 &&
        memcmp(b1.data(), b2.data(), b1.data_size()) != 0) {
      return false;
    }

    if (b1.references().size() != b2.references().size())
      return false;
  }

  {
    // Compare the references. They should point to blocks with the same id.
    BlockGraph::Block::ReferenceMap::const_iterator
        it1 = b1.references().begin();
    for (; it1 != b1.references().end(); ++it1) {
      BlockGraph::Block::ReferenceMap::const_iterator it2 =
          b2.references().find(it1->first);
      if (it2 == b2.references().end() ||
          it1->second.referenced()->id() != it2->second.referenced()->id()) {
        LOG(ERROR) << "References not equal.";
        return false;
      }
    }
  }

  if (b1.referrers().size() != b2.referrers().size())
    return false;

  {
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
  }

  return true;
}

// Compares two BlockGraphs to each other.
bool BlockGraphsEqual(const BlockGraph& b1,
                      const BlockGraph& b2,
                      BlockGraph::SerializationAttributes attributes) {
  if (b1.sections() != b2.sections() ||
      b1.blocks().size() != b2.blocks().size()) {
    return false;
  }

  // We manually compare iterate through the blocks and use BlocksEqual,
  // because they don't otherwise have a comparison operator.
  BlockGraph::BlockMap::const_iterator it1 = b1.blocks().begin();
  for (; it1 != b1.blocks().end(); ++it1) {
    BlockGraph::BlockMap::const_iterator it2 = b2.blocks().find(it1->first);
    if (it2 == b2.blocks().end())
      return false;

    if (!BlocksEqual(it1->second, it2->second, attributes))
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

bool SerializeRoundTripTest(
    const block_graph::BlockGraph& input_image,
    block_graph::BlockGraph::SerializationAttributes input_attributes,
    block_graph::BlockGraph* output_image) {
  core::ByteVector byte_vector_with_data;
  core::ScopedOutStreamPtr out_stream(
      core::CreateByteOutStream(std::back_inserter(byte_vector_with_data)));
  core::NativeBinaryOutArchive out_archive(out_stream.get());
  if (!input_image.Save(&out_archive, input_attributes))
    return false;
  if (!out_archive.Flush())
    return false;

  core::ScopedInStreamPtr in_stream(
      core::CreateByteInStream(byte_vector_with_data.begin(),
                               byte_vector_with_data.end()));
  core::NativeBinaryInArchive in_archive(in_stream.get());

  block_graph::BlockGraph::SerializationAttributes attributes;
  if (!output_image->Load(&in_archive, &attributes))
    return false;

  if (!BlockGraphsEqual(input_image, *output_image, input_attributes))
    return false;

  if (input_attributes != attributes)
    return false;

  if (input_attributes != block_graph::BlockGraph::DEFAULT) {
    // If we don't use the default flag for the serialization then the graph
    // shouldn't be equal.
    if (testing::BlockGraphsEqual(input_image,
                                  *output_image,
                                  BlockGraph::DEFAULT)) {
      return false;
    }
  }

  return true;
}

}  // namespace testing
