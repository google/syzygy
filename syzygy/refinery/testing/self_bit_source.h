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

#ifndef SYZYGY_REFINERY_TESTING_SELF_BIT_SOURCE_H_
#define SYZYGY_REFINERY_TESTING_SELF_BIT_SOURCE_H_

#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/core/bit_source.h"

namespace testing {

// A bit source that reads memory from our own process.
class SelfBitSource : public refinery::BitSource {
 public:
  ~SelfBitSource() override;

  // BitSource implementation.
  bool GetAll(const refinery::AddressRange& range, void* data_ptr) override;
  bool GetFrom(const refinery::AddressRange& range,
               size_t* data_cnt,
               void* data_ptr) override;
  bool HasSome(const refinery::AddressRange& range) override;
};

}  // namespace testing

#endif  // SYZYGY_REFINERY_TESTING_SELF_BIT_SOURCE_H_
