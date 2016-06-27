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
//
// Central place to house common unittest functionality for msf_lib.

#ifndef SYZYGY_MSF_UNITTEST_UTIL_H_
#define SYZYGY_MSF_UNITTEST_UTIL_H_

#include "syzygy/msf/msf_decl.h"
#include "syzygy/msf/msf_file.h"

namespace testing {

// Paths to various files.
extern const wchar_t kTestPdbFilePath[];

template <msf::MsfFileType T>
void EnsureMsfContentsAreIdentical(
    const msf::detail::MsfFileImpl<T>& msf_file,
    const msf::detail::MsfFileImpl<T>& msf_file_read) {
  DCHECK_EQ(msf_file.StreamCount(), msf_file_read.StreamCount());

  for (size_t i = 0; i < msf_file.StreamCount(); ++i) {
    msf::detail::MsfStreamImpl<T>* stream = msf_file.GetStream(i).get();
    msf::detail::MsfStreamImpl<T>* stream_read =
        msf_file_read.GetStream(i).get();

    DCHECK_NE(static_cast<msf::detail::MsfStreamImpl<T>*>(nullptr), stream);
    DCHECK_NE(static_cast<msf::detail::MsfStreamImpl<T>*>(nullptr),
              stream_read);

    CHECK_EQ(stream->length(), stream_read->length());

    std::vector<uint8_t> data(stream->length());
    std::vector<uint8_t> data_read(stream_read->length());
    if (data.size() != 0)
      CHECK(stream->ReadBytesAt(0, data.size(), &data.at(0)));
    if (data_read.size() != 0)
      CHECK(stream_read->ReadBytesAt(0, data_read.size(), &data_read.at(0)));

    // We don't use ContainerEq because upon failure this generates a
    // ridiculously long and useless error message. We don't use memcmp because
    // it doesn't given any context as to where the failure occurs.
    for (size_t j = 0; j < data.size(); ++j)
      CHECK_EQ(data[j], data_read[j]);
  }
}

}  // namespace testing

#endif  // SYZYGY_MSF_UNITTEST_UTIL_H_
