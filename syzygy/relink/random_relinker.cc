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

#include "syzygy/relink/random_relinker.h"

#include <algorithm>
#include "base/file_util.h"
#include "base/json/json_reader.h"
#include "base/values.h"
#include "syzygy/pe/decomposer.h"

using pe::Decomposer;

namespace {

// This is a linear congruent pseuodo random generator.
// See: http://en.wikipedia.org/wiki/Linear_congruential_generator.
class RandomNumberGenerator {
 public:
  explicit RandomNumberGenerator(int seed) : seed_(seed) {
  }

  int operator()(int n) {
    seed_ = seed_ * kA + kC;
    int ret = seed_ % n;
    DCHECK(ret >= 0 && ret < n);
    return ret;
  }

 private:
  static const int kA = 1103515245;
  static const int kC = 12345;

  // The generator is g(N + 1) = (g(N) * kA + kC) mod 2^32.
  // The unsigned 32 bit seed yields the mod 2^32 for free.
  uint32 seed_;
};

}  // namespace

RandomRelinker::RandomRelinker(
    const BlockGraph::AddressSpace& original_addr_space,
    BlockGraph* block_graph,
    int seed)
    : Relinker(original_addr_space, block_graph),
      seed_(seed) {
}

RandomRelinker::~RandomRelinker() {
}

bool RandomRelinker::Relink(const FilePath& input_dll_path,
                            const FilePath& input_pdb_path,
                            const FilePath& output_dll_path,
                            const FilePath& output_pdb_path,
                            int seed) {
  DCHECK(!input_dll_path.empty());
  DCHECK(!input_pdb_path.empty());
  DCHECK(!output_dll_path.empty());
  DCHECK(!output_pdb_path.empty());

  // Read and decompose the input image for starters.
  pe::PEFile input_dll;
  if (!input_dll.Init(input_dll_path)) {
    LOG(ERROR) << "Unable to read " << input_dll_path.value() << ".";
    return false;
  }

  Decomposer decomposer(input_dll, input_dll_path);
  Decomposer::DecomposedImage decomposed;
  if (!decomposer.Decompose(&decomposed, NULL,
                            Decomposer::STANDARD_DECOMPOSITION)) {
    LOG(ERROR) << "Unable to decompose " << input_dll_path.value() << ".";
    return false;
  }

  RandomRelinker relinker(decomposed.address_space, &decomposed.image, seed);
  if (!relinker.Relinker::Relink(decomposed.header, input_pdb_path,
                                 output_dll_path, output_pdb_path)) {
    LOG(ERROR) << "Unable to relink " << output_dll_path.value() << ".";
    return false;
  }

  return true;
}

bool RandomRelinker::ReorderCode(const IMAGE_SECTION_HEADER& section) {
  // We use a private pseudo random number generator to allow consistent
  // results across different CRTs and CRT versions.
  RandomNumberGenerator random_generator(seed_);

  BlockGraph::AddressSpace::Range section_range(
      RelativeAddress(section.VirtualAddress), section.Misc.VirtualSize);
  const char* name = reinterpret_cast<const char*>(section.Name);
  std::string name_str(name, strnlen(name, arraysize(section.Name)));

  // Duplicate the section in the new image.
  RelativeAddress start = builder().AddSegment(name_str.c_str(),
                                               section.Misc.VirtualSize,
                                               section.SizeOfRawData,
                                               section.Characteristics);
  AddressSpace::RangeMapConstIterPair section_blocks =
      original_addr_space().GetIntersectingBlocks(section_range.start(),
                                                  section_range.size());

  // Hold back the blocks within the section for reordering.
  AddressSpace::RangeMapConstIter& section_it = section_blocks.first;
  const AddressSpace::RangeMapConstIter& section_end =
      section_blocks.second;
  std::vector<BlockGraph::Block*> code_blocks;
  for (; section_it != section_end; ++section_it) {
    BlockGraph::Block* block = section_it->second;
    DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());
    code_blocks.push_back(block);
  }

  // Now reorder the code blocks and insert them into the
  // code segment in the new order.
  std::random_shuffle(code_blocks.begin(),
                      code_blocks.end(),
                      random_generator);
  RelativeAddress insert_at = start;
  for (size_t i = 0; i < code_blocks.size(); ++i) {
    BlockGraph::Block* block = code_blocks[i];

    if (!builder().address_space().InsertBlock(insert_at, block)) {
      LOG(ERROR) << "Unable to insert block '" << block->name()
          << "' at " << insert_at;
    }

    insert_at += block->size();
  }

  // Create the code section.
  uint32 code_size = insert_at - start;
  builder().AddSegment(".text",
                       code_size,
                       code_size,
                       IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                       IMAGE_SCN_MEM_READ);

  return true;
}
