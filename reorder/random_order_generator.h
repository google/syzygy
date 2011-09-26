
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
//
#ifndef SYZYGY_REORDER_RANDOM_ORDER_GENERATOR_H_
#define SYZYGY_REORDER_RANDOM_ORDER_GENERATOR_H_

#include "syzygy/reorder/reorderer.h"

namespace reorder {

// Orders blocks within sections using a pseudo-random shuffle.
class RandomOrderGenerator : public Reorderer::OrderGenerator {
 public:
  typedef Reorderer::UniqueTime UniqueTime;
  typedef Reorderer::Order Order;
  typedef BlockGraph::AddressSpace AddressSpace;

  explicit RandomOrderGenerator(int seed);
  virtual ~RandomOrderGenerator();

  // OrderGenerator implementation.
  virtual bool OnCodeBlockEntry(const BlockGraph::Block* block,
                                RelativeAddress address,
                                uint32 process_id,
                                uint32 thread_id,
                                const UniqueTime& time);
  virtual bool CalculateReordering(bool reorder_code,
                                   bool reorder_data,
                                   Order* order);

 private:
  const uint32 seed_;
};

}  // namespace reorder

#endif  // SYZYGY_REORDER_RANDOM_ORDER_GENERATOR_H_
