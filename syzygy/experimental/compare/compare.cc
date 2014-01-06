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
// This file contains the implementation of a block graph reconciliation
// algorithm. Essentially, it takes two block graphs from two different versions
// of the same binary, and creates mappings between blocks in the two block
// graphs. If two blocks are mapped it means that semantically they are the
// same function/piece of data in each version of the binary.
//
// The basic approach we use is to extract 'features' from the blocks. The
// blocks from both block graphs are sorted based on each individual feature,
// and blocks with like features are grouped into buckets. If there exists a
// bucket with only two blocks in it, one from each block graph, then we
// assume the blocks are semantically equivalent across the versions.
//
// Currently we have two features we use. The first is the physical content of
// the block, minus the actual values of any references. Blocks that contain
// identical code/values are very likely to be the same block across versions.
// The second is the decorated name of the block. Decorated names encode the
// original name of the function in source code, plus the names of the types
// passed in to it.
//
// These two approaches are complementary. It is possible that a refactor
// simply changed the name of a type or a function. In this case, the decorated
// names will have changed, but the block contents will not. Similarly, it is
// possible (and more likely) that the contents of a block have changed. If the
// API has not changed, the decorated names will be the same and the blocks
// will still be able to be matched.
//
// Once we've matched two blocks, we can use them as a basis for matching
// further blocks. If two blocks have identical content and have been matched,
// then we can assume that any blocks that they reference are identical. If
// they have identical referrers, we can then assume that the blocks that refer
// to them are identical. If in the process of mapping blocks, we whittle away
// the blocks in a bucket of some feature such that there remains only
//
// It is possible that two different features will want to match different
// pairs of blocks. For example, imagine a template function that is passed
// an enum, and imagine that the enum value is used within the function:
// Foo<typename SomeEnum, typename T>(SomeEnum enum_value, T* t). Imagine that
// in one binary kEnumValueFoo has value 0, but that in the second binary the
// enum has been changed and kEnumValueFoo now has value 1 and some other enum
// kEnumValueBar has value 0. Then in terms of block content,
// Foo<SomeEnum, Foo> and Foo<SomeEnum, Bar> will match across block-graphs.
// However, in terms of decorated names they will not match. It is pretty
// clear that in this case we prefer to match blocks by name. This pattern
// is actually seen in WebKit code. This situation is handled if we give
// priority to decorated names.
//
// Similarly, the opposite situation is also possible. Imagine a templated
// function that generates identical code regardless of the type that is
// passed in to it. In this case, code folding results in only one of these
// blocks surviving in each image. However, the name that is kept for the
// block is essentially random across all possible names. Thus, in one version
// of the binary Bar<T0> may have been kept, whereas in the other Bar<T1>
// made the cut. In this case, a match will be made based on identical code
// content. This situation is handled regardless of the feature that is
// given priority.

#include "syzygy/experimental/compare/compare.h"

#include <algorithm>

#include "base/logging.h"
#include "base/md5.h"
#include "syzygy/block_graph/block_hash.h"
#include "syzygy/common/comparable.h"
#include "syzygy/experimental/compare/block_compare.h"

namespace experimental {

using block_graph::BlockGraph;
using block_graph::ConstBlockVector;

namespace {

const size_t kInvalidIndex = -1;

// Features are properties of blocks that are used to match up blocks between
// block graphs. If there exists exactly one block in each graph with the same
// value for the given feature, the blocks are assumed to be the same. We
// currently use two features: block hash, and block name.
//
// The order of these features indicates the order of priority for making
// matches. For example, it is possible that feature 0 wants to match block
// A with match B, but that feature 1 wants to match block A with block C. In
// this case, A will be matched with B and an informational warning will be
// printed about the conflicting A/C match.
enum BlockFeatures {
  kNameFeature,
  kHashFeature,
  // This needs to come last.
  kFeatureCount
};

// Every index needs to store some metadata that is tied to each block. We
// use a single metadata store to reduce overhead.
struct BlockMetadata {
  BlockMetadata() : block(NULL) {
    for (size_t i = 0; i < kFeatureCount; ++i) {
      feature_index[i] = kInvalidIndex;
    }
  }

  const BlockGraph::Block* block;

  // Each FeatureIndex needs to be able to map from a block to that blocks index
  // in the blocks sorted by that feature.
  size_t feature_index[kFeatureCount];

  // The first feature stores hash-values for each block.
  block_graph::BlockHash block_hash;

  // The second feature uses the block name. This is stored explicitly with the
  // block. However, some decorated names contain explicit image addresses in
  // them, and need to be normalized for comparison. In such cases, we
  // populate this string. Otherwise, it is left empty.
  std::string block_name;
};

// The virtual base-class for a block feature.
class BlockFeature {
 public:
  explicit BlockFeature(size_t id)
      : id_(id) {
    DCHECK_GT(static_cast<size_t>(kFeatureCount), id);
  }

  // Initializes the metadata for this feature and the given @p block.
  virtual bool InitMetadata(BlockMetadata* metadata) const = 0;

  // Compares two blocks, returning their relative sort order (-1, 0, 1).
  virtual int Compare(const BlockMetadata& metadata0,
                      const BlockMetadata& metadata1) const = 0;

  // Returns the id associated with this feature.
  size_t id() const { return id_; }

 private:
  size_t id_;

  DISALLOW_COPY_AND_ASSIGN(BlockFeature);
};

// This is the generic data structure for an index over some feature of a
// block.
class FeatureIndex {
 public:
  static const size_t kInvalidFeatureBucket = -1;

  // Blocks with these attributes are ignored in the mapping.
  static const BlockGraph::BlockAttributes kIgnoredAttributes =
    BlockGraph::PADDING_BLOCK;

  // Initializes this feature index over the provided block graphs.
  FeatureIndex(const BlockFeature& block_feature,
               const BlockGraph& block_graph0,
               const BlockGraph& block_graph1);

  // This returns the number of unique features in the graph. (The number of
  // unique buckets the blocks were able to be split up into.)
  size_t size() const { return feature_infos_.size(); }

  // Returns true if the given block is mapped.
  bool BlockIsMapped(const BlockGraph::Block* block) const {
    size_t i = GetBlockIndex(block);
    return block_infos_[i].mapped;
  }

  // Returns the feature bucket that the given block lies in. If two blocks
  // lie in the same feature bucket, they are identical as far as that feature
  // is concerned.
  size_t GetFeatureBucket(const BlockGraph::Block* block) const {
    size_t i = GetBlockIndex(block);
    return block_infos_[i].feature_bucket;
  }

  // This returns true if the given feature index has 1 unique block remaining
  // from each block graph, false otherwise.
  bool ExistUniqueBlocks(size_t feature_bucket) const {
    DCHECK_GT(feature_infos_.size(), feature_bucket);
    return feature_infos_[feature_bucket].block_count[0] == 1 &&
        feature_infos_[feature_bucket].block_count[1] == 1;
  }

  // Same as ExistUniqueBlocks, but finds and returns the unique blocks as well.
  bool GetUniqueBlocks(size_t feature_bucket,
                       const BlockGraph::Block** block0,
                       const BlockGraph::Block** block1) const {
    DCHECK(block0 != NULL);
    DCHECK(block1 != NULL);

    *block0 = NULL;
    *block1 = NULL;

    if (!ExistUniqueBlocks(feature_bucket))
      return false;

    // Find the two unmapped blocks, and return them.
    const FeatureInfo& fi = feature_infos_[feature_bucket];
    int unmapped_blocks_found = 0;
    for (size_t i = fi.start; i < fi.end; ++i) {
      if (block_infos_[i].mapped)
        continue;
      ++unmapped_blocks_found;

      if (block_infos_[i].block_graph_index == 0) {
        DCHECK(*block0 == NULL);
        *block0 = block_infos_[i].metadata->block;
      } else {
        DCHECK_EQ(1U, block_infos_[i].block_graph_index);
        DCHECK(*block1 == NULL);
        *block1 = block_infos_[i].metadata->block;
      }

      if (unmapped_blocks_found == 2)
        break;
    }
    DCHECK_EQ(2, unmapped_blocks_found);

    return true;
  }

  // This marks the given blocks as mapped. This operation can cause up to two
  // feature ids to now return true when passed to exist_unique_blocks, thus
  // we have two return parameters. These will both be set to
  // kInvalidFeatureBucket if this is not the case, otherwise they will store
  // the affected feature bucket.
  void MarkAsMapped(const BlockGraph::Block* block0,
                    const BlockGraph::Block* block1,
                    size_t* unique_feature_bucket0,
                    size_t* unique_feature_bucket1) {
    DCHECK(unique_feature_bucket0 != NULL);
    DCHECK(unique_feature_bucket1 != NULL);
    *unique_feature_bucket0 = kInvalidFeatureBucket;
    *unique_feature_bucket1 = kInvalidFeatureBucket;

    size_t feature_bucket0 = MapBlock(block0, 0);
    size_t feature_bucket1 = MapBlock(block1, 1);

    if (ExistUniqueBlocks(feature_bucket0)) {
      *unique_feature_bucket0 = feature_bucket0;
    }

    if (feature_bucket0 != feature_bucket1 &&
        ExistUniqueBlocks(feature_bucket1)) {
      *unique_feature_bucket1 = feature_bucket1;
    }
  }

  // Returns the unmapped blocks from the given block-graph.
  void GetUnmappedBlocks(size_t block_graph_index,
                         ConstBlockVector* unmapped) const {
    DCHECK(block_graph_index == 0 || block_graph_index == 1);
    DCHECK(unmapped != NULL);

    unmapped->clear();
    for (size_t i = 0; i < block_infos_.size(); ++i) {
      if (!block_infos_[i].mapped &&
          block_infos_[i].block_graph_index == block_graph_index) {
        unmapped->push_back(block_infos_[i].metadata->block);
      }
    }
  }

  // Returns the metadata associated with a given block. This is used for
  // debugging purposes.
  static const BlockMetadata* GetBlockMetadata(const BlockGraph::Block* block) {
    BlockMetadataMap::const_iterator it = block_metadata_.find(block);
    if (it == block_metadata_.end())
      return NULL;
    return &it->second;
  }

 private:
  // Returns the index of the given block in this feature.
  size_t GetBlockIndex(const BlockGraph::Block* block) const {
    BlockMetadataMap::const_iterator it = block_metadata_.find(block);
    DCHECK(it != block_metadata_.end());
    size_t index = it->second.feature_index[feature_id_];
    DCHECK_GT(block_infos_.size(), index);
    return index;
  }

  // Populates block_infos_ and block_metadata_ with the blocks from the
  // given BlockGraph.
  bool AddBlocks(const BlockFeature& block_feature,
                 size_t block_graph_index,
                 const BlockGraph& block_graph) {
    DCHECK(block_graph_index == 0 || block_graph_index == 1);

    BlockGraph::BlockMap::const_iterator block_it =
        block_graph.blocks().begin();
    for (; block_it != block_graph.blocks().end(); ++block_it) {
      const BlockGraph::Block* block = &block_it->second;

      if (block->attributes() & kIgnoredAttributes)
        continue;

      // Ensure that an entry exists in block_metadata_.
      BlockMetadataMap::iterator metadata_it = block_metadata_.find(block);
      if (metadata_it == block_metadata_.end()) {
        BlockMetadata metadata;
        metadata.block = block;
        metadata_it = block_metadata_.insert(
            std::make_pair(block, metadata)).first;
      }

      // Initialize any metadata for this feature.
      if (!block_feature.InitMetadata(&metadata_it->second))
        return false;

      // Add this block to block_infos_.
      BlockInfo block_info(&metadata_it->second,
                           block_graph_index,
                           block_feature.id());
      block_infos_.push_back(block_info);
    }

    return true;
  }

  // Maps the given block, returning its feature bucket.
  size_t MapBlock(const BlockGraph::Block* block,
                  size_t block_graph_index) {
    DCHECK(block_graph_index == 0 || block_graph_index == 1);

    BlockMetadataMap::const_iterator metadata_it =
        block_metadata_.find(block);
    DCHECK(metadata_it != block_metadata_.end());
    const BlockMetadata& metadata(metadata_it->second);
    DCHECK_EQ(block, metadata.block);

    size_t index = metadata.feature_index[feature_id_];
    DCHECK_GT(block_infos_.size(), index);
    BlockInfo& block_info = block_infos_[index];
    DCHECK_EQ(&metadata, block_info.metadata);
    DCHECK_EQ(block_graph_index, block_info.block_graph_index);
    DCHECK(!block_info.mapped);

    size_t feature_bucket = block_info.feature_bucket;
    DCHECK_GT(feature_infos_.size(), feature_bucket);
    FeatureInfo& feature_info = feature_infos_[feature_bucket];

    block_info.mapped = true;
    --feature_info.block_count[block_graph_index];

    // NOTE: It may be tempting to try to move 'feature_info.start' forward
    //    or 'feature_info.end' backward as blocks are mapped, but this is no
    //    more expensive than doing a search through the full original size of
    //    the bucket when its entries becomes unique. In fact, it will be
    //    cheaper overall this way, as not all buckets will get to this point.

    return feature_bucket;
  }

  // This stores information for each block. The blocks are stored in their
  // feature sorted order. We allow default constructor/copy for STL
  // compatibility.
  struct BlockInfo {
    BlockInfo(BlockMetadata* metadata,
              size_t block_graph_index,
              size_t feature_bucket)
      : metadata(metadata),
        block_graph_index(block_graph_index),
        feature_bucket(feature_bucket),
        mapped(false) {
      DCHECK(metadata != NULL);
    }

    BlockMetadata* metadata;
    size_t block_graph_index;
    size_t feature_bucket;
    bool mapped;
  };
  std::vector<BlockInfo> block_infos_;

  // This is used as a sort functor for BlockInfos.
  class BlockInfoSortFunctor {
   public:
    explicit BlockInfoSortFunctor(const BlockFeature& block_feature)
        : block_feature(block_feature) {
    }

    bool operator()(const BlockInfo& block_info0,
                    const BlockInfo& block_info1) {
      return block_feature.Compare(*block_info0.metadata,
                                   *block_info1.metadata) < 0;
    }
   private:
    const BlockFeature& block_feature;
  };

  // This stores information regarding the per unique feature in the index.
  struct FeatureInfo {
    FeatureInfo()
        : start(0), end(0) {
      block_count[0] = 0;
      block_count[1] = 0;
    }

    // The start (inclusive) of the feature in the _block_infos index.
    size_t start;
    // Ths end (exlusive) of the feature in the _block_infos index.
    size_t end;
    // The number of blocks from the each block-graph left in the index sharing
    // this feature id.
    size_t block_count[2];
  };
  std::vector<FeatureInfo> feature_infos_;

  // There is a sinlge instance of block metadata shared across all
  // FeatureIndex objects.
  typedef std::map<const BlockGraph::Block*, BlockMetadata> BlockMetadataMap;
  static BlockMetadataMap block_metadata_;

  // This is copied from the BlockFeature provided in the constructor.
  size_t feature_id_;

  DISALLOW_COPY_AND_ASSIGN(FeatureIndex);
};

FeatureIndex::BlockMetadataMap FeatureIndex::block_metadata_;

FeatureIndex::FeatureIndex(const BlockFeature& block_feature,
                           const BlockGraph& block_graph0,
                           const BlockGraph& block_graph1)
    : feature_id_(block_feature.id()) {
  // Nothing to do if the block graphs are both empty!
  if (block_graph0.blocks().empty() && block_graph1.blocks().empty())
    return;

  // Add the blocks to block_infos_, and initialize metadata.
  block_infos_.reserve(block_graph0.blocks().size() +
      block_graph1.blocks().size());
  if (!AddBlocks(block_feature, 0, block_graph0))
    return;
  if (!AddBlocks(block_feature, 1, block_graph1))
    return;

  // Sort block_infos_.
  BlockInfoSortFunctor block_info_sort(block_feature);
  std::sort(block_infos_.begin(),
            block_infos_.end(),
            block_info_sort);

  // Assign unique feature IDs, and build out the FeatureInfo array.
  // Simultaneously, fill out BlockMetadata::feature_index.
  size_t feature_bucket = 0;
  block_infos_[0].feature_bucket = feature_bucket;
  block_infos_[0].metadata->feature_index[feature_id_] = 0;
  feature_infos_.resize(1);
  size_t i = 1;
  for (; i < block_infos_.size(); ++i) {
    int c = block_feature.Compare(*block_infos_[i - 1].metadata,
                                  *block_infos_[i].metadata);
    if (c != 0) {
      feature_infos_.back().end = i;

      FeatureInfo feature_info;
      feature_info.start = i;
      feature_infos_.push_back(feature_info);
      ++feature_bucket;
    }

    // Ensure that this block's feature_index has not yet been assigned to.
    DCHECK_EQ(kInvalidIndex,
              block_infos_[i].metadata->feature_index[feature_id_]);

    block_infos_[i].feature_bucket = feature_bucket;
    block_infos_[i].metadata->feature_index[feature_id_] = i;

    // Update the number of blocks that fall within this feature bucket.
    size_t bgi = block_infos_[i].block_graph_index;
    feature_infos_.back().block_count[bgi]++;
  }
  feature_infos_.back().end = i;
  ++feature_bucket;

  LOG(INFO) << "Feature " << feature_id_ << " has " << feature_bucket
            << " buckets.";

#ifndef NDEBUG
  // Ensure that all metadata's have been assigned valid feature indices.
  BlockMetadataMap::const_iterator it = block_metadata_.begin();
  for (; it != block_metadata_.end(); ++it) {
    size_t index = it->second.feature_index[feature_id_];
    DCHECK_GT(block_infos_.size(), index);
  }
#endif
}

class BlockHashFeature : public BlockFeature {
 public:
  BlockHashFeature() : BlockFeature(kHashFeature) {
  }

  virtual bool InitMetadata(BlockMetadata* metadata) const {
    DCHECK(metadata != NULL);
    metadata->block_hash.Hash(metadata->block);
    return true;
  }

  virtual int Compare(const BlockMetadata& metadata0,
                      const BlockMetadata& metadata1) const {
    int c = metadata0.block_hash.Compare(metadata1.block_hash);
    if (c != 0)
      return c;

    return BlockCompare(metadata0.block, metadata1.block);
  }
};

class BlockNameFeature : public BlockFeature {
 public:
  BlockNameFeature() : BlockFeature(kNameFeature) {
  }

  virtual bool InitMetadata(BlockMetadata* metadata) const {
    // TODO(chrisha): Look for occurrences of 0x[a-fA-F0-9]{8}. If found,
    //     replace them with 0xXXXXXXXX.
    return true;
  }

  // Compare block names, but using the name in the metadata struct if there
  // is one.
  virtual int Compare(const BlockMetadata& metadata0,
                      const BlockMetadata& metadata1) const {
    base::StringPiece s0 = metadata0.block->name();
    if (!metadata0.block_name.empty())
      s0 = metadata0.block_name;

    base::StringPiece s1 = metadata1.block->name();
    if (!metadata1.block_name.empty())
      s1 = metadata1.block_name;

    return s0.compare(s1);
  }
};

// This is for storing a list of unique referrers keyed by destination address.
typedef std::map<BlockGraph::Offset,
                 std::pair<const BlockGraph::Block*, size_t> >
    UniqueReferrerMap;

// This builds a unique referrer map for the given block.
void BuildUniqueReferrerMap(const BlockGraph::Block* block,
                            UniqueReferrerMap* refmap) {
  DCHECK(block != NULL);
  DCHECK(refmap != NULL);

  BlockGraph::Block::ReferrerSet::const_iterator ref =
      block->referrers().begin();
  for (; ref != block->referrers().end(); ++ref) {
    const BlockGraph::Block* parent = ref->first;
    BlockGraph::Offset src_offset = ref->second;
    DCHECK(parent != NULL);

    BlockGraph::Block::ReferenceMap::const_iterator it =
        parent->references().find(src_offset);
    DCHECK(it != parent->references().end());

    BlockGraph::Offset dst_offset = it->second.offset();

    UniqueReferrerMap::iterator refmap_it = refmap->find(dst_offset);
    if (refmap_it == refmap->end()) {
      refmap_it = refmap->insert(
          std::make_pair(dst_offset,
                         std::make_pair(parent, 0))).first;
    }
    ++refmap_it->second.second;
  }
}

class BlockGraphMapper {
 public:
  // Builds the mapping between the two given block graphs, and if provided,
  // populates the vector of unmapped blocks left in each block graph.
  bool BuildMapping(const BlockGraph& bg0,
                    const BlockGraph& bg1,
                    BlockGraphMapping* mapping,
                    ConstBlockVector* unmapped0,
                    ConstBlockVector* unmapped1);

 private:
  // Internally, most of the work is done by the FeatureIndex objects.
  scoped_ptr<FeatureIndex> feature_indices_[kFeatureCount];

  // Maps the two given blocks, using these blocks as a starting point to find
  // other mappings.
  bool MapBlocks(const BlockGraph::Block* block0,
                 const BlockGraph::Block* block1);

  // This is used to schedule a mapping. The blocks must not already be
  // mapped.
  bool ScheduleMapping(const BlockGraph::Block* block0,
                       const BlockGraph::Block* block1);

  // Maps the blocks in the given bucket of the given feature. They must be
  // unique.
  bool ScheduleUniqueBucketMapping(size_t feature_id,
                                   size_t feature_bucket);

  // Maps the references of the given block.
  bool ScheduleReferenceMappings(const BlockGraph::Block* block0,
                                 const BlockGraph::Block* block1,
                                 bool blocks_identical);

  // Maps the referrers of the given blocks.
  bool ScheduleReferrerMappings(const BlockGraph::Block* block0,
                                const BlockGraph::Block* block1,
                                bool blocks_identical);

  // Maps the pair of blocks, but only if they are both currently
  // unmapped.
  bool ScheduleIfUnmapped(const BlockGraph::Block* block0,
                          const BlockGraph::Block* block1);

  // This is used to store the mapping that was passed in to BuildMapping.
  BlockGraphMapping* mapping_;

  // This is used to store pending mappings.
  BlockGraphMapping pending_;
  BlockGraphMapping pending_reverse_;
};

bool BlockGraphMapper::BuildMapping(const BlockGraph& bg0,
                                    const BlockGraph& bg1,
                                    BlockGraphMapping* mapping,
                                    ConstBlockVector* unmapped0,
                                    ConstBlockVector* unmapped1) {
  DCHECK(mapping != NULL);
  mapping_ = mapping;
  mapping_->clear();

  // Build the feature indices.
  BlockHashFeature hash_feature;
  feature_indices_[kHashFeature].reset(
      new FeatureIndex(hash_feature, bg0, bg1));
#ifdef USE_BLOCK_NAME_FEATURE
  BlockNameFeature name_feature;
  feature_indices_[kNameFeature].reset(
      new FeatureIndex(name_feature, bg0, bg1));
#endif

  // Iterate through each index.
  for (size_t i = 0; i < kFeatureCount; ++i) {
    // Iterate through the unique feature values. For every feature value we
    // find that contains only a single block per block-graph, we can infer that
    // these blocks are identical. Use these as a root for matching up blocks.
    for (size_t j = 0; j < feature_indices_[i]->size(); ++j) {
      if (feature_indices_[i]->ExistUniqueBlocks(j)) {
        if (!ScheduleUniqueBucketMapping(i, j)) {
          return false;
        }
      }
    }
  }

  // Loop until there are no more blocks left to map.
  while (!pending_.empty()) {
    const BlockGraph::Block* block0 = pending_.begin()->first;
    const BlockGraph::Block* block1 = pending_.begin()->second;
    pending_.erase(pending_.begin());
    pending_reverse_.erase(block1);

    if (!MapBlocks(block0, block1))
      return false;
  }
  DCHECK(pending_.empty());
  DCHECK(pending_reverse_.empty());

  // Forget the mapping output variable.
  mapping_ = NULL;

  // If provided, fill out the list of unmapped blocks.
  if (unmapped0 != NULL)
    feature_indices_[0]->GetUnmappedBlocks(0, unmapped0);
  if (unmapped1 != NULL)
    feature_indices_[0]->GetUnmappedBlocks(1, unmapped1);

  return true;
}

bool BlockGraphMapper::ScheduleMapping(const BlockGraph::Block* block0,
                                       const BlockGraph::Block* block1) {
  // Neither block should yet be mapped.
  DCHECK(!feature_indices_[0]->BlockIsMapped(block0));
  DCHECK(!feature_indices_[0]->BlockIsMapped(block1));

  // Use the pending_ and pending_reverse_ to ensure that neither of these
  // blocks are already scheduled for mapping. If they are, then we ignore
  // this request.

  BlockGraphMapping::const_iterator it = pending_.find(block0);
  if (it != pending_.end()) {
#ifndef NDEBUG
    if (it->second != block1) {
      // This is not an error, as higher priority features have precedence.
      // But, it's interesting to know if this happens.
      // In this case, block0 was already mapped to another block, block2.
      // block2 is in the same blockgraph as block1.
      const BlockGraph::Block* block2 = it->second;
      const BlockMetadata* meta0 = FeatureIndex::GetBlockMetadata(block0);
      const BlockMetadata* meta1 = FeatureIndex::GetBlockMetadata(block1);
      const BlockMetadata* meta2 = FeatureIndex::GetBlockMetadata(block2);
    }
#endif

    // This is a duplicate mapping.
    return true;
  }

  it = pending_reverse_.find(block1);
  if (it != pending_reverse_.end()) {
#ifndef NDEBUG
    if (it->second != block0) {
      // This is not an error, as higher priority features have precedence.
      // But, it's interesting to know if this happens.
      // In this case, block1 was already mapped to another block, block2.
      // block2 is in the same blockgraph as block0.
      const BlockGraph::Block* block2 = it->second;
      const BlockMetadata* meta0 = FeatureIndex::GetBlockMetadata(block0);
      const BlockMetadata* meta1 = FeatureIndex::GetBlockMetadata(block1);
      const BlockMetadata* meta2 = FeatureIndex::GetBlockMetadata(block2);
    }
#endif

    // This is a duplicate mapping.
    return true;
  }

  // Create the pending mapping.
  pending_.insert(std::make_pair(block0, block1));
  pending_reverse_.insert(std::make_pair(block1, block0));
  return true;
}

bool BlockGraphMapper::ScheduleUniqueBucketMapping(size_t feature_id,
                                                   size_t feature_bucket) {
  DCHECK_GT(static_cast<size_t>(kFeatureCount), feature_id);

  const BlockGraph::Block* block0 = NULL;
  const BlockGraph::Block* block1 = NULL;

  bool result = feature_indices_[feature_id]->GetUniqueBlocks(feature_bucket,
                                                              &block0,
                                                              &block1);
  DCHECK(result);
  return ScheduleMapping(block0, block1);
}

bool BlockGraphMapper::MapBlocks(const BlockGraph::Block* block0,
                                 const BlockGraph::Block* block1) {
  // Determine if these blocks are identical. We use the hash feature to
  // do that.
  // TODO(chrisha): A weaker hash, that ignores constants in the code.
  size_t hash_bucket0 =
      feature_indices_[kHashFeature]->GetFeatureBucket(block0);
  size_t hash_bucket1 =
      feature_indices_[kHashFeature]->GetFeatureBucket(block1);
  bool blocks_identical = hash_bucket0 == hash_bucket1;

  // Add the blocks to the output structure.
  mapping_->insert(std::make_pair(block0, block1));

  // Map the blocks in each feature. If the mapping causes any other feature
  // buckets to become unique, pursue those as well.
  for (size_t i = 0; i < kFeatureCount; ++i) {
    size_t unique_bucket0 = FeatureIndex::kInvalidFeatureBucket;
    size_t unique_bucket1 = FeatureIndex::kInvalidFeatureBucket;
    feature_indices_[i]->MarkAsMapped(block0, block1,
        &unique_bucket0, &unique_bucket1);

    if (unique_bucket0 != FeatureIndex::kInvalidFeatureBucket) {
      if (!ScheduleUniqueBucketMapping(i, unique_bucket0))
        return false;
    }

    if (unique_bucket1 != FeatureIndex::kInvalidFeatureBucket) {
      if (!ScheduleUniqueBucketMapping(i, unique_bucket1))
        return false;
    }
  }

  // Explore backwards and forwards in the reference tree to look for more
  // mappings.
  if (!ScheduleReferenceMappings(block0, block1, blocks_identical))
    return false;
  return ScheduleReferrerMappings(block0, block1, blocks_identical);
}

bool BlockGraphMapper::ScheduleReferenceMappings(
    const BlockGraph::Block* block0,
    const BlockGraph::Block* block1,
    bool blocks_identical) {
  // Nothing to do?
  if (block1->references().size() == 0)
    return true;

  // If the blocks are not identical, then we can only match children if
  // the block has only one child.
  if (!blocks_identical) {
    if (block0->references().size() != 1 || block1->references().size() != 1)
      return true;
  }

  // The blocks have compared as identical. Hence, they have references at
  // the same offsets. We walk through the maps simultaneously. We take for
  // granted that the std::map sorts based on the key.
  BlockGraph::Block::ReferenceMap::const_iterator it0 =
      block0->references().begin();
  BlockGraph::Block::ReferenceMap::const_iterator it1 =
      block1->references().begin();
  for (; it0 != block0->references().end(); ++it0, ++it1) {
    const BlockGraph::Block* block0 = it0->second.referenced();
    const BlockGraph::Block* block1 = it1->second.referenced();
    if (!ScheduleIfUnmapped(block0, block1))
      return false;
  }

  return true;
}

bool BlockGraphMapper::ScheduleReferrerMappings(const BlockGraph::Block* block0,
                                                const BlockGraph::Block* block1,
                                                bool blocks_identical) {
  if (block1->referrers().size() == 0)
    return true;

  // If the blocks are not identical, then we can only match parents if
  // the block has only one referrer.
  // NOTE: We're not comparing the destination offset of the blocks.
  //     Should we be?
  if (!blocks_identical) {
    if (block0->references().size() != 1 || block1->references().size() != 1)
      return true;

    BlockGraph::Block::ReferrerSet::const_iterator it0 =
        block0->referrers().begin();
    BlockGraph::Block::ReferrerSet::const_iterator it1 =
        block1->referrers().begin();

    const BlockGraph::Block* block0 = it0->first;
    const BlockGraph::Block* block1 = it1->first;
    return ScheduleIfUnmapped(block0, block1);
  }

  UniqueReferrerMap refmap0, refmap1;
  BuildUniqueReferrerMap(block0, &refmap0);
  BuildUniqueReferrerMap(block1, &refmap1);

  UniqueReferrerMap::const_iterator ref0 = refmap0.begin();
  for (; ref0 != refmap0.end(); ++ref0) {
    // We are only interested in destinations that have a unique referrer
    // in each block graph.
    if (ref0->second.second != 1)
      continue;

    UniqueReferrerMap::const_iterator ref1 = refmap1.find(ref0->first);
    if (ref1 == refmap1.end() || ref1->second.second != 1)
      continue;

    const BlockGraph::Block* block0 = ref0->second.first;
    const BlockGraph::Block* block1 = ref1->second.first;
    if (!ScheduleIfUnmapped(block0, block1))
      return false;
  }

  return true;
}

bool BlockGraphMapper::ScheduleIfUnmapped(const BlockGraph::Block* block0,
                                          const BlockGraph::Block* block1) {
  // Schedule the blocks for mapping if they arent
  if (feature_indices_[0]->BlockIsMapped(block0) ||
      feature_indices_[0]->BlockIsMapped(block1))
    return true;

  return ScheduleMapping(block0, block1);
}

}  // namespace

bool BuildBlockGraphMapping(const BlockGraph& bg1,
                            const BlockGraph& bg2,
                            BlockGraphMapping* mapping,
                            ConstBlockVector* unmapped1,
                            ConstBlockVector* unmapped2) {
  DCHECK(mapping != NULL);

  // Pass the real work off to the BlockGraphMapper defined above.
  BlockGraphMapper mapper;
  return mapper.BuildMapping(bg1, bg2, mapping, unmapped1, unmapped2);
}

bool ReverseBlockGraphMapping(const BlockGraphMapping& mapping,
                              BlockGraphMapping* reverse_mapping) {
  DCHECK(reverse_mapping != NULL);

  reverse_mapping->clear();
  BlockGraphMapping::const_iterator it = mapping.begin();
  for (; it != mapping.end(); ++it) {
    bool inserted = reverse_mapping->insert(
        std::make_pair(it->second, it->first)).second;
    if (!inserted) {
      LOG(ERROR) << "Input mapping not reversible.";
      return false;
    }
  }

  DCHECK_EQ(mapping.size(), reverse_mapping->size());

  return true;
}

}  // namespace experimental
