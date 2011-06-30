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

#include "syzygy/core/serialization.h"
#include <algorithm>
#include <stdio.h>

namespace core {

FileOutStream::FileOutStream(FILE* file) : file_(file) {
  DCHECK(file != NULL);
}

bool FileOutStream::Write(size_t length, const Byte* bytes) {
  return fwrite(bytes, sizeof(Byte), length, file_) == length;
}

FileInStream::FileInStream(FILE* file) : file_(file) {
  DCHECK(file != NULL);
}

bool FileInStream::Read(size_t length, Byte* bytes) {
  return fread(bytes, sizeof(Byte), length, file_) == length;
}

}  // namespace core
