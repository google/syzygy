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

#include "syzygy/refinery/core/address.h"

#include "base/numerics/safe_math.h"

namespace refinery {

bool AddressRange::IsValid() const {
  if (!size_)
    return false;

  base::CheckedNumeric<Address> range_end = addr_;
  range_end += size_;
  return range_end.IsValid();
}

Address AddressRange::end() const {
  DCHECK(IsValid());
  return addr_ + size_;
}

bool AddressRange::operator==(const AddressRange& other) const {
  return addr_ == other.addr_ && size_ == other.size_;
}

bool AddressRange::Intersects(const AddressRange& other) const {
  DCHECK(IsValid());
  DCHECK(other.IsValid());

  return start() < other.end() && end() > other.start();
}

bool AddressRange::Spans(const AddressRange& other) const {
  DCHECK(IsValid());
  DCHECK(other.IsValid());

  return start() <= other.start() && end() >= other.end();
}

}  // namespace refinery
