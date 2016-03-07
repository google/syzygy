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

#ifndef SYZYGY_REORDER_RANDOM_ORDER_GENERATOR_H_
#define SYZYGY_REORDER_RANDOM_ORDER_GENERATOR_H_

#include "syzygy/reorder/reorderer.h"

namespace reorder {

// Orders blocks within sections using a pseudo-random shuffle.
class RandomOrderGenerator : public Reorderer::OrderGenerator {
 public:
  explicit RandomOrderGenerator(int seed);
  virtual ~RandomOrderGenerator();

  // OrderGenerator implementation.
  virtual bool OnCodeBlockEntry(const BlockGraph::Block* block,
                                RelativeAddress address,
                                uint32_t process_id,
                                uint32_t thread_id,
                                const UniqueTime& time) override;
  virtual bool CalculateReordering(const PEFile& pe_file,
                                   const ImageLayout& image,
                                   bool reorder_code,
                                   bool reorder_data,
                                   Order* order) override;

 private:
  const uint32_t seed_;
};

}  // namespace reorder

#endif  // SYZYGY_REORDER_RANDOM_ORDER_GENERATOR_H_
