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

#include "syzygy/core/unittest_util.h"

namespace testing {

using core::BlockGraph;

// Compares two Blocks to each other.
bool BlocksEqual(const BlockGraph::Block& b1, const BlockGraph::Block& b2) {
  // Compare the basic block properties.
  if (b1.id() != b2.id() || b1.type() != b2.type() ||
      b1.size() != b2.size() || b1.alignment() != b2.alignment() ||
      strcmp(b1.name(), b2.name()) != 0 || b1.addr() != b2.addr() ||
      b1.section() != b2.section() || b1.attributes() != b2.attributes() ||
      b1.source_ranges() != b2.source_ranges() ||
      b1.labels() != b2.labels() || b1.owns_data() != b2.owns_data() ||
      b1.data_size() != b2.data_size()) {
    return false;
  }

  // Both data pointers should be null or non-null.
  if ((b1.data() == NULL) != (b2.data() == NULL))
    return false;

  // Compare the data.
  if (b1.data_size() > 0 &&
      memcmp(b1.data(), b2.data(), b1.data_size()) != 0) {
    return false;
  }

  if (b1.references().size() != b2.references().size())
    return false;

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
bool BlockGraphsEqual(const BlockGraph& b1, const BlockGraph& b2) {
  if (b1.blocks().size() != b2.blocks().size())
    return false;

  BlockGraph::BlockMap::const_iterator it1 = b1.blocks().begin();
  for (; it1 != b1.blocks().end(); ++it1) {
    BlockGraph::BlockMap::const_iterator it2 = b2.blocks().find(it1->first);
    if (it2 == b2.blocks().end())
      return false;

    if (!BlocksEqual(it1->second, it2->second))
      return false;
  }

  return true;
}

}  // namespace testing
