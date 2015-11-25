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

#include "syzygy/refinery/process_state/layer_data.h"

#include "gtest/gtest.h"
#include "syzygy/pe/pe_file.h"

namespace refinery {

TEST(PESignatureHasherTest, BasicTest) {
  PESignatureHasher hasher;

  pe::PEFile::Signature s1(L"PathA", core::AbsoluteAddress(0U), 1, 2, 3);
  pe::PEFile::Signature s2(s1);
  pe::PEFile::Signature s3(L"PathA", core::AbsoluteAddress(3U), 2, 1, 0);

  ASSERT_EQ(hasher(s1), hasher(s2));
  ASSERT_NE(hasher(s1), hasher(s3));
}

TEST(ModuleLayerDataTest, BasicTest) {
  ModuleLayerData data;

  // Should not find something when searching in empty data.
  pe::PEFile::Signature retrieved_sig;
  ASSERT_FALSE(data.Find(0, &retrieved_sig));

  pe::PEFile::Signature sig(L"Path", core::AbsoluteAddress(0U), 1, 2, 3);
  ASSERT_EQ(kNoModuleId, data.Find(sig));

  // FindOrIndex with a new signature should succeed.
  ModuleId retrieved_id = data.FindOrIndex(sig);
  ASSERT_NE(kNoModuleId, retrieved_id);

  // Ensure indexed modules can be found.
  ASSERT_EQ(retrieved_id, data.Find(sig));
  ASSERT_TRUE(data.Find(retrieved_id, &retrieved_sig));
  ASSERT_EQ(sig, retrieved_sig);

  // Second call to FindOrIndex should also work.
  ASSERT_EQ(retrieved_id, data.FindOrIndex(sig));
}

}  // namespace refinery
