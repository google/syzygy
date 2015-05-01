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
// Declares a partial BlockGraphOrdererInterface that provides an implementation
// for the 'name' member function.

#ifndef SYZYGY_BLOCK_GRAPH_ORDERERS_NAMED_ORDERER_H_
#define SYZYGY_BLOCK_GRAPH_ORDERERS_NAMED_ORDERER_H_

#include "syzygy/block_graph/orderer.h"

namespace block_graph {
namespace orderers {

// Implements the 'name' member function of BlockGraphOrdererInterface.
// The user must define the static variable:
//
//   const char DerivedType::kOrdererName[];
//
// @tparam DerivedType the type of the derived class.
template<class DerivedType>
class NamedOrdererImpl : public BlockGraphOrdererInterface {
 public:
  // Gets the name of this orderer.
  //
  // @returns the name of this orderer.
  virtual const char* name() const override {
    return DerivedType::kOrdererName;
  }
};

}  // namespace orderers
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_ORDERERS_NAMED_ORDERER_H_
