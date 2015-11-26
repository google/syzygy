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

#ifndef SYZYGY_REFINERY_DETECTORS_UNITTEST_UTIL_H_
#define SYZYGY_REFINERY_DETECTORS_UNITTEST_UTIL_H_

#include "gtest/gtest.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/testing/self_bit_source.h"
#include "syzygy/refinery/types/type_repository.h"

namespace testing {

class LFHDetectorTest : public testing::Test {
 protected:
  LFHDetectorTest();
  void SetUp() override;
  void TearDown() override;
  scoped_refptr<refinery::TypeRepository> repo() const { return repo_; }

  refinery::BitSource* bit_source() { return &bit_source_; }
  refinery::Address AllocateLFHBucket(size_t block_size);

 private:
  testing::ScopedSymbolPath scoped_symbol_path_;
  ScopedHeap scoped_heap_;
  testing::SelfBitSource bit_source_;
  scoped_refptr<refinery::TypeRepository> repo_;
};

}  // namespace testing

#endif  // SYZYGY_REFINERY_DETECTORS_UNITTEST_UTIL_H_
