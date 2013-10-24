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
// Defines OperationInterface, which all PEHacker operations must implement.

#ifndef SYZYGY_PEHACKER_OPERATION_H_
#define SYZYGY_PEHACKER_OPERATION_H_

#include "base/values.h"
#include "syzygy/block_graph/block_graph.h"

namespace pehacker {

class OperationInterface {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // Virtual destructor.
  virtual ~OperationInterface() { }

  // @returns the name of this operation.
  virtual const char* name() const = 0;

  // Initializes this operation with the given configuration. This will only
  // ever be called once for a given operation object.
  // @param policy The policy to use in guiding the operation.
  // @param operation The configuration for this operation.
  // @returns true on success, false otherwise.
  virtual bool Init(const TransformPolicyInterface* policy,
                    const base::DictionaryValue* operation) = 0;

  // Applies this operation to the given block-graph. This will only be called
  // after a successful call to Init. This will only ever be called once for a
  // given operation object.
  // @param policy The policy to use in guiding the operation.
  // @param block_graph The decomposed PE image on which to apply the operation.
  // @param header_block The PE header block.
  // @returns true on success, false otherwise.
  virtual bool Apply(const TransformPolicyInterface* policy,
                     BlockGraph* block_graph,
                     BlockGraph::Block* header_block) = 0;
};

}  // namespace pehacker

#endif  // SYZYGY_PEHACKER_OPERATION_H_
