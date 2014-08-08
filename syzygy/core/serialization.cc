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

#include "syzygy/core/serialization.h"

#include <windows.h>  // NOLINT
#include <dbghelp.h>
#include <stdio.h>
#include <algorithm>

#include "base/time/time.h"

namespace core {

FileOutStream::FileOutStream(FILE* file) : file_(file) {
  DCHECK(file != NULL);
}

bool FileOutStream::Write(size_t length, const Byte* bytes) {
  return fwrite(bytes, sizeof(Byte), length, file_) == length;
}

bool FileOutStream::Flush() {
  ::fflush(file_);
  return true;
}

FileInStream::FileInStream(FILE* file) : file_(file) {
  DCHECK(file != NULL);
}

bool FileInStream::ReadImpl(size_t length, Byte* bytes, size_t* bytes_read) {
  DCHECK(bytes != NULL);
  DCHECK(bytes_read != NULL);
  *bytes_read = ::fread(bytes, sizeof(Byte), length, file_);

  if (*bytes_read == length)
    return true;

  // If we didn't read the full number of bytes expected, figure out why. It's
  // not an error if we're at the end of the stream.
  if (!::feof(file_))
    return false;

  return true;
}

// Serialization of base::Time.
// We serialize to 'number of seconds since epoch' (represented as a double)
// as this is consistent regardless of the underlying representation used in
// base::Time (which may vary wrt timer resolution).

bool Save(const base::Time& time, OutArchive* out_archive) {
  DCHECK(out_archive != NULL);
  return out_archive->Save(time.ToDoubleT());
}

bool Load(base::Time* time, InArchive* in_archive) {
  DCHECK(in_archive != NULL);
  double t;
  if (!in_archive->Load(&t))
    return false;
  *time = base::Time::FromDoubleT(t);
  return true;
}

// Serialization of OMAP, defined in dbghelp.h.

bool Save(const OMAP& omap, OutArchive* out_archive) {
  DCHECK(out_archive != NULL);
  return out_archive->Save(omap.rva) &&
      out_archive->Save(omap.rvaTo);
}

bool Load(OMAP* omap, InArchive* in_archive) {
  DCHECK(omap != NULL);
  DCHECK(in_archive != NULL);
  return in_archive->Load(&omap->rva) &&
      in_archive->Load(&omap->rvaTo);
}

}  // namespace core
