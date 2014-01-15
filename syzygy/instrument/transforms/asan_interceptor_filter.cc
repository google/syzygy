// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/instrument/transforms/asan_interceptor_filter.h"

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/block_hash.h"

namespace instrument {
namespace transforms {

using block_graph::BlockGraph;
using block_graph::BlockHash;

void ASanInterceptorFilter::InitializeCRTFunctionHashes() {
  // Hashes common between MSVS 2010 and MSVS 2013.
  function_hash_map_["memchr"].insert("3549cc2f365403c679287c34325b8925");
  function_hash_map_["strcspn"].insert("c2e8480d30ceeeb2e9e39b545c82c98c");
  function_hash_map_["strlen"].insert("20e07f6e772c47e6cbfc13db5eafa757");
  function_hash_map_["strpbrk"].insert("9af2e6d499d25ad4628c58a25dbcde1e");
  function_hash_map_["strspn"].insert("79b6a33a1b03b482be14afff061d7c68");
  function_hash_map_["strncpy"].insert("aed1dd2372364f66f4d126eefb073070");
  function_hash_map_["strncat"].insert("9cc9e9a57cdd695606caf6cbf532d88e");

  // Hashes specific to MSVS 2010.
  function_hash_map_["memcpy"].insert("da1805f40d6e92f6ac497c66ac969e61");
  function_hash_map_["memmove"].insert("da1805f40d6e92f6ac497c66ac969e61");
  function_hash_map_["memset"].insert("5fcb11b79692c753845cf26dfa42e74c");
  function_hash_map_["strrchr"].insert("f849347be44ddb17a4fc3c64b90f8cca");
  function_hash_map_["strcmp"].insert("865502e059de8a9dc6cee8ef05b1a586");
  function_hash_map_["strstr"].insert("cdfbaae199dcc8272681c021fab9d664");
  function_hash_map_["wcsrchr"].insert("e049d7b7cb421013b2151b2070302def");

  // Hashes specific to MSVS 2013.
  function_hash_map_["memcpy"].insert("270406ea8a9e931f2c0db8a7f0b5d698");
  function_hash_map_["memmove"].insert("270406ea8a9e931f2c0db8a7f0b5d698");
  function_hash_map_["memset"].insert("4900d834c35bb195ab8af6f91d648d6d");
  function_hash_map_["strrchr"].insert("17575b2dc3a7fd3b277d0cd798f507df");
  function_hash_map_["strcmp"].insert("3de87a84bf545bd485f846c1b9456bcb");
  function_hash_map_["strstr"].insert("1926bd8c94118f97819d604ec5afee30");
  function_hash_map_["wcsrchr"].insert("86cb28d7c68ae6f62c694f2e3239b725");
}

bool ASanInterceptorFilter::ShouldIntercept(const BlockGraph::Block* block) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);

  FunctionHashMap::iterator func_iter = function_hash_map_.find(block->name());

  if (func_iter == function_hash_map_.end())
    return false;

  block_graph::BlockHash block_hash(block);
  std::string hash_val = base::MD5DigestToBase16(block_hash.md5_digest);

  HashSet::iterator hash_iter = func_iter->second.find(hash_val);

  if (hash_iter == func_iter->second.end())
    return false;

  return true;
}

void ASanInterceptorFilter::AddBlockToHashMap(BlockGraph::Block* block) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);
  BlockHash block_hash(block);
  function_hash_map_[block->name()].insert(
      base::MD5DigestToBase16(block_hash.md5_digest));
}

}  // namespace transforms
}  // namespace instrument
