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
//
// The CoffFileWriter is the final step in the processing pipeline of COFF
// files; it expects a fully laid out image and writes it to disk, only
// performing the most basic sanity checks.

#ifndef SYZYGY_PE_COFF_FILE_WRITER_H_
#define SYZYGY_PE_COFF_FILE_WRITER_H_

#include "base/files/file_path.h"
#include "syzygy/pe/image_layout.h"

namespace pe {

// A CoffFileWriter writes a fully laid out COFF image to disk. Contrary to
// its PE counterpart, the COFF writer does not alter the contents of the
// blocks before writing. In particular, it does not patch references.
class CoffFileWriter {
 public:
  // Construct a file writer for the specified COFF image layout. The layout
  // must be valid for a COFF file, with all references resolved, offsets
  // fixed and relocation data present and accurate.
  //
  // @param image_layout the image layout to write.
  explicit CoffFileWriter(const ImageLayout* image_layout);

  // Write the image to the specified file. The file is overwritten by this
  // call, whether it succeeds or not.
  //
  // @param path the path of the file to write.
  // @returns true on success, false on failure.
  bool WriteImage(const base::FilePath& path);

 private:
  // The image layout to write to disk.
  const ImageLayout* image_layout_;

 private:
  DISALLOW_COPY_AND_ASSIGN(CoffFileWriter);
};

}  // namespace pe

#endif  // SYZYGY_PE_COFF_FILE_WRITER_H_
