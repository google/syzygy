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
// Internal implementation details for msf_writer.h. Not meant to be included
// directly.

#ifndef SYZYGY_MSF_MSF_WRITER_H_
#define SYZYGY_MSF_MSF_WRITER_H_

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "syzygy/msf/msf_decl.h"
#include "syzygy/msf/msf_file.h"
#include "syzygy/msf/msf_stream.h"

namespace msf {
namespace detail {

// This class is used to write an MSF file to disk given a list of MsfStreams.
// It will create a header and directory inside the MSF file that describe
// the page layout of the streams in the file.
template <MsfFileType T>
class MsfWriterImpl {
 public:
  MsfWriterImpl();
  virtual ~MsfWriterImpl();

  // Writes the given MsfFileImpl to disk with the given file name.
  // @param msf_path the path of the MSF file to write.
  // @param msf_file the MSF file to be written.
  // @returns true on success, false otherwise.
  bool Write(const base::FilePath& msf_path, const MsfFileImpl<T>& msf_file);

 protected:
  // Append the contents of the stream onto the file handle at the offset. The
  // contents of the file are padded to reach the next page boundary in the
  // output stream. The indices of the written pages are appended to
  // @p pages_written, while @p page_count is updated to reflect the total
  // number of pages written to disk.
  bool AppendStream(MsfStreamImpl<T>* stream,
                    std::vector<uint32_t>* pages_written,
                    uint32_t* page_count);

  // Writes the MSF header after the directory has been written.
  bool WriteHeader(const std::vector<uint32_t>& root_directory_pages,
                   uint32_t directory_size,
                   uint32_t page_count);

  // The current file handle open for writing.
  base::ScopedFILE file_;

 private:
  DISALLOW_COPY_AND_ASSIGN(MsfWriterImpl);
};

}  // namespace detail

using MsfWriter = detail::MsfWriterImpl<kGenericMsfFileType>;

}  // namespace msf

#include "syzygy/msf/msf_writer_impl.h"

#endif  // SYZYGY_MSF_MSF_WRITER_H_
