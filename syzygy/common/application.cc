// Copyright 2012 Google Inc.
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

namespace common {

AppImplBase::AppImplBase()
    : in_(stdin), out_(stdout), err_(stderr) {
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

}  // namespace common
