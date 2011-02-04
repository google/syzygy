// Copyright 2010 Google Inc.
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
#ifndef SAWBUCK_IMAGE_UTIL_PDB_WRITER_H_
#define SAWBUCK_IMAGE_UTIL_PDB_WRITER_H_

#include <vector>
#include "base/file_path.h"
#include "sawbuck/image_util/pdb_stream.h"

// This class is used to write a pdb file to disk given a list of PdbStreams.
// It will create a header and directory inside the pdb file that describe
// the page layout of the streams in the file.
class PdbWriter {
 public:
  PdbWriter();
  ~PdbWriter();

  // Write a pdb file to disk. pdb_path specifies where the file should be
  // written relative to the current working directory, and pdb_streams is a
  // PdbStreamList that contains the streams to be written to the file.
  bool Write(const FilePath& pdb_path, const PdbStreamList& pdb_streams);

 private:
  // Info about a stream that's been written to the file.
  struct StreamInfo {
    uint32 offset;  // Byte offset into the file.
    uint32 size;    // Size in bytes of the stream.
  };
  typedef std::vector<StreamInfo> StreamInfoList;

  // Write an unsigned 32 bit value to the output file.
  bool WriteUint32(const char* func,
                   const char* desc,
                   FILE* file,
                   uint32 value);

  // Pad the output file with zeros to the boundary of the current page.
  bool PadToPageBoundary(const char* func,
                         FILE* file,
                         uint32 offset,
                         uint32* padding);

  // Append the contents of the stream onto the file handle at the offset. The
  // contents of the file are padded to reach the next page boundary in the
  // output stream.
  bool AppendStream(FILE* file,
                    const PdbStream* pdb_stream,
                    uint32* bytes_written);

  // Write the set of directory pages to the file handle.
  bool WriteDirectory(FILE* file,
                      const StreamInfoList& stream_info_list,
                      uint32* directory_length,
                      uint32* bytes_written);

  // Writes the list of root pages which form the MSF directory.
  bool WriteDirectoryPages(FILE* file,
                           uint32 start_page,
                           uint32 dir_size,
                           uint32* dir_pages_size,
                           uint32* bytes_written);

  // Writes the MSF/PDB file header once you know where the directory root
  // pages are and what the directory size and the total size of the file are.
  bool WriteHeader(FILE* file,
                   size_t dir_root_page,
                   size_t dir_root_size,
                   size_t dir_size,
                   size_t file_size);
};

#endif  // SAWBUCK_IMAGE_UTIL_PDB_WRITER_H_
