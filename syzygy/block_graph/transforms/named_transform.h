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
// Declares a partial BlockGraphTransformInterface implementation that provides
// an implementation for the 'name' member function. Declares a similar
// implementation of a BasicBlockSubGraphTransformInterface. Both
// implementations refer to the same static variable so that a transform need
// only be named once, and be an implementation of both transform types.

#ifndef SYZYGY_BLOCK_GRAPH_TRANSFORMS_NAMED_TRANSFORM_H_
#define SYZYGY_BLOCK_GRAPH_TRANSFORMS_NAMED_TRANSFORM_H_

#include "syzygy/block_graph/transform.h"

namespace block_graph {
namespace transforms {

// Implements the 'name' member function of BlockGraphTransformInterface.
// The user must define the static variable:
//
//   const char DerivedType::kTransformName[];
//
// @tparam DerivedType the type of the derived class.
template<class DerivedType>
class NamedBlockGraphTransformImpl : public BlockGraphTransformInterface {
 public:
  // Gets the name of this transform.
  //
  // @returns the name of this transform.
  virtual const char* name() const override {
    return DerivedType::kTransformName;
  }
};

// Implements the 'name' member function of BasicBlockGraphTransformInterface.
// The user must define the static variable:
//
//   const char DerivedType::kTransformName[];
//
// @tparam DerivedType the type of the derived class.
template<class DerivedType>
class NamedBasicBlockSubGraphTransformImpl
    : public BasicBlockSubGraphTransformInterface {
 public:
  // Gets the name of this transform.
  //
  // @returns the name of this transform.
  virtual const char* name() const override {
    return DerivedType::kTransformName;
  }
};

// Implements the 'name' member function of ImageLayoutTransformInterface.
// The user must define the static variable:
//
//   const char DerivedType::kTransformName[];
//
// @tparam DerivedType the type of the derived class.
template<class DerivedType>
class NamedImageLayoutTransformImpl
  : public ImageLayoutTransformInterface {
 public:
  // Gets the name of this transform.
  //
  // @returns the name of this transform.
  virtual const char* name() const override {
    return DerivedType::kTransformName;
  }
};

}  // namespace transforms
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_TRANSFORMS_NAMED_TRANSFORM_H_
