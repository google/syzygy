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

#ifndef SYZYGY_MSF_MSF_READER_H_
#define SYZYGY_MSF_MSF_READER_H_

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "syzygy/msf/msf_constants.h"
#include "syzygy/msf/msf_data.h"
#include "syzygy/msf/msf_decl.h"
#include "syzygy/msf/msf_file.h"
#include "syzygy/msf/msf_file_stream.h"
#include "syzygy/msf/msf_stream.h"

namespace msf {
namespace detail {

// This class is used to read an MSF file from disk, populating an MsfFileImpl
// object with its streams.
template <MsfFileType T>
class MsfReaderImpl {
 public:
  MsfReaderImpl() {}

  virtual ~MsfReaderImpl() {}

  // Reads an MSF, populating the given MsfFileImpl object with the streams.
  //
  // @note Once use of the above Read function variants has been eliminated,
  //     MsfReaderImpl will become stateless and simply populate an MsfFileImpl.
  //
  // @param msf_path the MSF file to read.
  // @param msf_file the empty MsfFileImpl object to be filled in.
  // @returns true on success, false otherwise.
  bool Read(const base::FilePath& msf_path, MsfFileImpl<T>* msf_file);

 private:
  DISALLOW_COPY_AND_ASSIGN(MsfReaderImpl);
};

}  // namespace detail

using MsfReader = detail::MsfReaderImpl<kGenericMsfFileType>;

}  // namespace msf

#include "syzygy/msf/msf_reader_impl.h"

#endif  // SYZYGY_MSF_MSF_READER_H_
