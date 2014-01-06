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

#ifndef SYZYGY_COMMON_COMPARABLE_H_
#define SYZYGY_COMMON_COMPARABLE_H_

namespace common {

// A 'mixin' class for endowing any class with comparison operators,
// provided it implements a 3-way compare function with signature
// 'int Compare(const T& other) const;'.
template<typename T> class Comparable {
 public:
  bool operator==(const T& other) const {
    return reinterpret_cast<const T*>(this)->Compare(other) == 0;
  }

  bool operator!=(const T& other) const {
    return reinterpret_cast<const T*>(this)->Compare(other) != 0;
  }

  bool operator<=(const T& other) const {
    return reinterpret_cast<const T*>(this)->Compare(other) <= 0;
  }

  bool operator<(const T& other) const {
    return reinterpret_cast<const T*>(this)->Compare(other) < 0;
  }

  bool operator>=(const T& other) const {
    return reinterpret_cast<const T*>(this)->Compare(other) >= 0;
  }

  bool operator>(const T& other) const {
    return reinterpret_cast<const T*>(this)->Compare(other) > 0;
  }
};

}  // namespace common

#endif  // SYZYGY_COMMON_COMPARABLE_H_
