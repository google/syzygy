// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/testing/toolchain.h"

#include "base/environment.h"
#include "base/string_util.h"
#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"

namespace testing {

namespace {

typedef std::vector<std::string> StringVector;
typedef std::set<std::string> StringSet;

const char kPathVar[] = "PATH";
const char kPathSep = ';';

void AppendPaths(const StringVector& paths,
                 StringSet* new_path_set,
                 StringVector* new_paths) {
  DCHECK_NE(reinterpret_cast<StringSet*>(NULL), new_path_set);
  DCHECK_NE(reinterpret_cast<StringVector*>(NULL), new_paths);

  for (size_t i = 0; i < paths.size(); ++i) {
    const std::string& path = paths[i];
    std::string lower_path = StringToLowerASCII(path);
    std::pair<StringSet::iterator, bool> result =
        new_path_set->insert(lower_path);

    // If the path was already in the path set, then don't append it.
    if (!result.second)
      continue;

    new_paths->push_back(path);
  }
}

}  // namespace

// This brings in auto-generated data in the form a macro definitions. It is
// included here to keep the scope as narrow as possible.
#include "syzygy/testing/toolchain_paths.gen"

const char kToolchainPaths[] = TOOLCHAIN_PATHS;
const wchar_t kCompilerPath[] = COMPILER_PATH;
const wchar_t kLinkerPath[] = LINKER_PATH;

// Undefine the macros brought in from toolchain_paths.gen.
#undef TOOLCHAIN_PATHS
#undef COMPILER_PATH
#undef LINKER_PATH

void SetToolchainPaths() {
  base::Environment* env = base::Environment::Create();
  ASSERT_NE(reinterpret_cast<base::Environment*>(NULL), env);

  std::string path;
  ASSERT_TRUE(env->GetVar(kPathVar, &path));

  StringVector paths;
  base::SplitString(path, kPathSep, &paths);

  StringVector toolchain_paths;
  base::SplitString(std::string(kToolchainPaths), kPathSep, &toolchain_paths);

  StringSet new_path_set;
  StringVector new_paths;
  AppendPaths(toolchain_paths, &new_path_set, &new_paths);
  AppendPaths(paths, &new_path_set, &new_paths);

  std::string new_path = JoinString(new_paths, kPathSep);
  ASSERT_TRUE(env->SetVar(kPathVar, new_path));
}

}  // namespace testing
