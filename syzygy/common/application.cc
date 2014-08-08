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
//
// Defines member function for a generic application implementation base
// class (empty implementation).

#include "syzygy/common/application.h"

#include "base/file_util.h"
#include "base/files/file_enumerator.h"
#include "base/files/file_path.h"

namespace common {

AppImplBase::AppImplBase(const base::StringPiece& name)
    : in_(stdin), out_(stdout), err_(stderr) {
  name_.assign(name.begin(), name.end());
}

bool AppImplBase::ParseCommandLine(const CommandLine* command_line) {
  return true;
}

bool AppImplBase::SetUp() {
  return true;
}

int AppImplBase::Run() {
  return 0;
}

void AppImplBase::TearDown() {
}

base::FilePath AppImplBase::AbsolutePath(const base::FilePath& path) {
  if (path.empty())
    return base::FilePath();

  base::FilePath temp(base::MakeAbsoluteFilePath(path));
  if (temp.empty())
    return path;
  else
    return temp;
}

bool AppImplBase::AppendMatchingPaths(const base::FilePath& pattern,
                                      std::vector<base::FilePath>* matches) {
  DCHECK(matches != NULL);
  bool found_a_match = false;

  // Whether the pattern is an existing file or not, we expand it as a glob.
  // If it's a file, it'll match itself and nothing else.
  base::FileEnumerator files(AbsolutePath(pattern.DirName()),
                             false,
                             base::FileEnumerator::FILES,
                             pattern.BaseName().value());
  while (true) {
    base::FilePath file = files.Next();
    if (file.empty())
      break;

    DCHECK(file.IsAbsolute());

    found_a_match = true;
    matches->push_back(file);
  }

  return found_a_match;
}

}  // namespace common
