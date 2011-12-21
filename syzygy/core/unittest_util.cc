// Copyright 2011 Google Inc.
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

#include "syzygy/core/unittest_util.h"

#include "base/path_service.h"

namespace testing {

FilePath GetSrcRelativePath(const wchar_t* rel_path) {
  FilePath src_dir;
  PathService::Get(base::DIR_SOURCE_ROOT, &src_dir);
  return src_dir.Append(rel_path);
}

FilePath GetExeRelativePath(const wchar_t* rel_path) {
  FilePath exe_dir;
  PathService::Get(base::DIR_EXE, &exe_dir);
  return exe_dir.Append(rel_path);
}

FilePath GetOutputRelativePath(const wchar_t* rel_path) {
#if defined(_DEBUG)
  // TODO(chrisha): Expose $(ProjectDir) and $(OutputDir) via defines in the
  //     project gyp file.
  static const wchar_t kOutputDir[] = L"Debug";
#else
#if defined(NDEBUG)
  static const wchar_t kOutputDir[] = L"Release";
#else
#error Unknown build profile.
#endif
#endif

  FilePath src_dir;
  PathService::Get(base::DIR_SOURCE_ROOT, &src_dir);
  src_dir = src_dir.Append(L"build");
  src_dir = src_dir.Append(kOutputDir);
  return src_dir.Append(rel_path);
}

FilePath GetExeTestDataRelativePath(const wchar_t* rel_path) {
  FilePath exe_dir;
  PathService::Get(base::DIR_EXE, &exe_dir);
  FilePath test_data = exe_dir.Append(L"test_data");
  return test_data.Append(rel_path);
}

}  // namespace testing
