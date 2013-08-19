// Copyright 2013 Google Inc. All Rights Reserved.
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
// Declares the various classes used to implement the tagging mechanism in
// basic-blocks. Tags are a way to attach user data to objects in a basic-block
// subgraph. Once the subgraph has been reassembled as a collection of blocks
// the tags can be used to find the block, offset and size of the object in its
// concrete form.

#ifndef SYZYGY_BLOCK_GRAPH_TAGS_H_
#define SYZYGY_BLOCK_GRAPH_TAGS_H_

#include <map>
#include <set>
#include <vector>

#include "syzygy/block_graph/block_graph.h"

namespace block_graph {

// A tag is nothing more than a void pointer to some user data. This guarantees
// uniqueness across clients and makes it semantically meaningful to the end
// user as well.
typedef const void* Tag;
typedef std::set<Tag> TagSet;

// This is an enumeration of the types of objects that may be tagged. The object
// type will be available in the metadata associated with the user data.
enum TaggedObjectType {
  kReferenceTag,
  kInstructionTag,
  kSuccessorTag,
  kBasicCodeBlockTag,
  kBasicDataBlockTag,
};

// This is the information that is associated with a particular user tag. It
// will be populated by the BlockBuilder when a BasicBlockSubGraph is made
// concrete.
//
// It is possible for a tagged object to have size 0 if that object has actually
// been elided from the final representation. This can happen with successors
// when a straight path execution is sufficient, for example (or the references
// contained within them).
struct TagInfo {
  TagInfo(TaggedObjectType type,
          BlockGraph::Block* block,
          BlockGraph::Offset offset,
          BlockGraph::Size size)
      : type(type), block(block), offset(offset), size(size) {
    DCHECK(block != NULL);
  }

  // The type of object that was tagged.
  TaggedObjectType type;
  // The block where the tagged object resides.
  BlockGraph::Block* block;
  // The offset in the block where the tagged object resides.
  BlockGraph::Offset offset;
  // The length of the tagged object.
  BlockGraph::Size size;
};

// Holds a collection of tag infos.
typedef std::vector<TagInfo> TagInfos;

// This holds a resume of all the tag metadata that was attached to a basic
// block subgraph. This is populated by the BlockBuilder when the subgraph is
// made concrete.
typedef std::map<Tag, TagInfos> TagInfoMap;

}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_TAGS_H_
