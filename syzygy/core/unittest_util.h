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
//
// Declares utilities for building unittests dealing with functionality from
// core_lib.

#ifndef SYZYGY_CORE_UNITTEST_UTIL_H_
#define SYZYGY_CORE_UNITTEST_UTIL_H_

#include "syzygy/core/serialization.h"

namespace testing {

// This defines a simple test of serialization for a given object. Returns
// true on success, false otherwise. The data object must be default
// constructible and comparable.
template<class Data> bool TestSerialization(const Data& data) {
  core::ByteVector bytes;

  core::ScopedOutStreamPtr out_stream;
  out_stream.reset(core::CreateByteOutStream(std::back_inserter(bytes)));
  core::NativeBinaryOutArchive out_archive(out_stream.get());
  if (!out_archive.Save(data))
    return false;

  core::ScopedInStreamPtr in_stream;
  in_stream.reset(core::CreateByteInStream(bytes.begin(), bytes.end()));
  core::NativeBinaryInArchive in_archive(in_stream.get());
  Data data_copy;
  if (!in_archive.Load(&data_copy))
    return false;

  // Ensure the two elements are the same after a roundtrip through the
  // serialization engine.
  return (data == data_copy);
};

// Same as above, but serializes to the given file, which has to be opened
// in read-write mode.
template<class Data> bool TestSerialization(const Data& data, FILE* file) {
  core::FileOutStream out_stream(file);
  core::NativeBinaryOutArchive out_archive(&out_stream);
  if (!out_archive.Save(data))
    return false;

  // Flush the output and rewind the file.
  fflush(file);
  fseek(file, 0, SEEK_SET);

  core::FileInStream in_stream(file);
  core::NativeBinaryInArchive in_archive(&in_stream);
  Data data_copy;
  if (!in_archive.Load(&data_copy))
    return false;

  // Ensure the two elements are the same after a roundtrip through the
  // serialization engine.
  return (data == data_copy);
};

}  // namespace testing

#endif  // SYZYGY_CORE_UNITTEST_UTIL_H_
