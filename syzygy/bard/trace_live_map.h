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
//
// Declares a template class for handling conversions from trace file
// pointers to live pointers.
#ifndef SYZYGY_BARD_TRACE_LIVE_MAP_H_
#define SYZYGY_BARD_TRACE_LIVE_MAP_H_

#include <map>

#include "base/synchronization/lock.h"

namespace bard {

// A template class that holds a bidirectional map, for handling conversions
// from trace file pointers to live pointers, since the addresses for the
// live ones are not the same.
// This class is thread safe for simultaneous access accross multiple threads.
// @tparam T The type of object that the class is mapping.
template <typename T>
class TraceLiveMap {
 public:
  using Map = std::map<T, T>;

  bool AddMapping(T trace, T live);
  bool RemoveMapping(T trace, T live);

  bool GetLiveFromTrace(T trace, T* live);
  bool GetTraceFromLive(T live, T* trace);

  // Clears this map.
  void Clear();

  // @returns true iff this map is empty.
  bool Empty() const { return trace_live_.empty() && live_trace_.empty(); }

  // @name Simple accessors.
  // @{
  const Map& trace_live() const { return trace_live_; }
  const Map& live_trace() const { return live_trace_; }
  // @}

 private:
  Map trace_live_;
  Map live_trace_;

  base::Lock lock_;
};

}  // namespace bard

#include "syzygy/bard/trace_live_map_impl.h"

#endif  // SYZYGY_BARD_TRACE_LIVE_MAP_H_
