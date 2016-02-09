// Copyright 2016 Google Inc. All Rights Reserved.
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

#include "syzygy/refinery/types/unittest_util.h"

#include <windows.h>

#include <vector>

#include "base/scoped_native_library.h"
#include "base/win/scoped_handle.h"
#include "syzygy/core/unittest_util.h"

namespace testing {

namespace {

typedef bool (*GetExpectedVftableVAsPtr)(unsigned buffer_size,
                                         unsigned long long* vftable_vas,
                                         unsigned* count);

}  // namespace

void PdbCrawlerVTableTestBase::PerformGetVFTableRVAsTest(
    const wchar_t* pdb_path_str,
    const wchar_t* dll_path_str) {
  DCHECK(pdb_path_str);  DCHECK(dll_path_str);

  // Crawl the pdb for vftable RVAs.
  base::hash_set<refinery::Address> vftable_rvas;
  ASSERT_NO_FATAL_FAILURE(GetVFTableRVAs(pdb_path_str, &vftable_rvas));

  // Get the expectation from the dll.
  base::FilePath dll_path = testing::GetSrcRelativePath(dll_path_str);

  base::ScopedNativeLibrary module(dll_path);
  ASSERT_TRUE(module.is_valid());

  GetExpectedVftableVAsPtr get_vas = reinterpret_cast<GetExpectedVftableVAsPtr>(
      module.GetFunctionPointer("GetExpectedVftableVAs"));
  ASSERT_TRUE(get_vas != nullptr);

  unsigned buffer_size = 10U;
  std::vector<uint64_t> vftable_vas;
  vftable_vas.resize(buffer_size);
  unsigned count = 0U;
  ASSERT_TRUE(get_vas(buffer_size, &vftable_vas.at(0), &count));

  // Validate the expectation.
  ASSERT_LE(count, vftable_rvas.size());

  for (size_t i = 0; i < count; ++i) {
    refinery::Address expected_rva =
        static_cast<refinery::RelativeAddress>(vftable_vas[i]) -
        reinterpret_cast<refinery::RelativeAddress>(module.get());
    EXPECT_NE(vftable_rvas.end(), vftable_rvas.find(expected_rva));
  }
}

}  // namespace testing
