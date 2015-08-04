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

#include "syzygy/bard/causal_link.h"

#include "base/time/time.h"
#include "gtest/gtest.h"

namespace bard {

TEST(CausalLinkTest, TestBasics) {
  CausalLink link;

  EXPECT_FALSE(link.IsSignaled());

  link.Signal();
  link.Wait();
  EXPECT_TRUE(link.IsSignaled());
  EXPECT_TRUE(link.TimedWait(base::TimeDelta::FromMilliseconds(10)));

  link.Reset();
  EXPECT_FALSE(link.IsSignaled());
  EXPECT_FALSE(link.TimedWait(base::TimeDelta::FromMilliseconds(10)));
}

}  // namespace bard
