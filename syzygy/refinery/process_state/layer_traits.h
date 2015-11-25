// Copyright 2015 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_REFINERY_PROCESS_STATE_LAYER_TRAITS_H_
#define SYZYGY_REFINERY_PROCESS_STATE_LAYER_TRAITS_H_

#include "syzygy/refinery/process_state/layer_data.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

template <typename T>
class LayerTraits {
 public:
  typedef NoData DataType;
};

template<>
class LayerTraits<Module> {
 public:
  typedef ModuleLayerData DataType;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_PROCESS_STATE_LAYER_TRAITS_H_
