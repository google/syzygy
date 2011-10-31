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
#ifndef SYZYGY_RELINK_RANDOM_RELINKER_H_
#define SYZYGY_RELINK_RANDOM_RELINKER_H_

#include "syzygy/relink/relinker.h"

namespace relink {

// The random relinker is used to relink a module with the blocks in each
// section randomly shuffled. The random relinker causes all blocks to be
// explicitly instantiated, with each section having no implicit uninitialized
// virtual address space.
class RandomRelinker : public Relinker {
 public:
  // Default constructor.
  explicit RandomRelinker(uint32 seed);

  // Sets the seed to use when generating a random ordering.  The
  // seed defaults to 0 if not set.
  void set_seed(int seed);

 private:
  DISALLOW_COPY_AND_ASSIGN(RandomRelinker);

  // Overrides for base class methods.
  bool SetupOrdering(const PEFile& pe_file,
                     const ImageLayout& image,
                     Reorderer::Order* order) OVERRIDE;
  bool ReorderSection(size_t section_index,
                      const ImageLayout::SectionInfo& section,
                      const Reorderer::Order& order) OVERRIDE;

  // The seed for the random ordering.
  const uint32 seed_;
};

}  // namespace relink

#endif  // SYZYGY_RELINK_RANDOM_RELINKER_H_
