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

#include "syzygy/pdb/pdb_reader.h"

#include "base/logging.h"
#include "base/strings/string_util.h"
#include "syzygy/pdb/pdb_file_stream.h"

namespace pdb {

namespace {

bool GetFileSize(FILE* file, uint32* size) {
  DCHECK(file != NULL);
  DCHECK(size != NULL);

  if (fseek(file, 0, SEEK_END) != 0) {
    LOG(ERROR) << "Failed seeking to end of file.";
    return false;
  }

  long temp = ftell(file);
  if (temp == -1L) {
    LOG(ERROR) << "Failed to read stream position.";
    return false;
  }
  DCHECK_GT(temp, 0);

  (*size) = static_cast<uint32>(temp);
  return true;
}

uint32 GetNumPages(const PdbHeader& header, uint32 num_bytes) {
  return (num_bytes + header.page_size - 1) / header.page_size;
}

}  // namespace

bool PdbReader::Read(const base::FilePath& pdb_path, PdbFile* pdb_file) {
  DCHECK(pdb_file != NULL);

  pdb_file->Clear();

  scoped_refptr<RefCountedFILE> file(new RefCountedFILE(
      base::OpenFile(pdb_path, "rb")));
  if (!file->file()) {
    LOG(ERROR) << "Unable to open '" << pdb_path.value() << "'.";
    return false;
  }

  // Get the file size.
  uint32 file_size = 0;
  if (!GetFileSize(file->file(), &file_size)) {
    LOG(ERROR) << "Unable to determine size of '" << pdb_path.value() << "'.";
    return false;
  }

  PdbHeader header = { 0 };

  // Read the header from the first page in the file. The page size we use here
  // is irrelevant as after reading the header we get the actual page size in
  // use by the PDB and from then on use that.
  uint32 header_page = 0;
  scoped_refptr<PdbFileStream> header_stream(new PdbFileStream(
      file, sizeof(header), &header_page, kPdbPageSize));
  if (!header_stream->Read(&header, 1)) {
    LOG(ERROR) << "Failed to read PDB file header.";
    return false;
  }

  // Sanity checks.
  if (header.num_pages * header.page_size != file_size) {
    LOG(ERROR) << "Invalid PDB file size.";
    return false;
  }

  if (memcmp(header.magic_string, kPdbHeaderMagicString,
             sizeof(kPdbHeaderMagicString)) != 0) {
    LOG(ERROR) << "Invalid PDB magic string.";
    return false;
  }

  // Load the directory page list (a sequence of uint32 page numbers that is
  // itself written across multiple root pages). To do this we need to know how
  // many pages are required to represent the directory, then we load a stream
  // containing that many page pointers from the root pages array.
  int num_dir_pages = static_cast<int>(GetNumPages(header,
                                                   header.directory_size));
  scoped_refptr<PdbFileStream> dir_page_stream(new PdbFileStream(
      file, num_dir_pages * sizeof(uint32),
      header.root_pages, header.page_size));
  scoped_ptr<uint32[]> dir_pages(new uint32[num_dir_pages]);
  if (dir_pages.get() == NULL) {
    LOG(ERROR) << "Failed to allocate directory pages.";
    return false;
  }
  if (!dir_page_stream->Read(dir_pages.get(), num_dir_pages)) {
    LOG(ERROR) << "Failed to read directory page stream.";
    return false;
  }

  // Load the actual directory.
  int dir_size = static_cast<int>(header.directory_size / sizeof(uint32));
  scoped_refptr<PdbFileStream> dir_stream(new PdbFileStream(
      file, header.directory_size, dir_pages.get(), header.page_size));
  std::vector<uint32> directory(dir_size);
  if (!dir_stream->Read(&directory[0], dir_size)) {
    LOG(ERROR) << "Failed to read directory stream.";
    return false;
  }

  // Iterate through the streams and construct PdbStreams.
  const uint32& num_streams = directory[0];
  const uint32* stream_lengths = &(directory[1]);
  const uint32* stream_pages = &(directory[1 + num_streams]);

  uint32 page_index = 0;
  for (uint32 stream_index = 0; stream_index < num_streams; ++stream_index) {
    pdb_file->AppendStream(new PdbFileStream(file,
                                             stream_lengths[stream_index],
                                             stream_pages + page_index,
                                             header.page_size));
    page_index += GetNumPages(header, stream_lengths[stream_index]);
  }

  return true;
}

}  // namespace pdb
