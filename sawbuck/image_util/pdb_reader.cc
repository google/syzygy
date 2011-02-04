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
#include "sawbuck/image_util/pdb_reader.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_util.h"

PdbReader::PdbReader() {
}

PdbReader::~PdbReader() {
}

bool PdbReader::Read(const FilePath& pdb_path, PdbStreamList* pdb_streams) {
  file_util::ScopedFILE file(file_util::OpenFile(pdb_path, "rb"));
  if (!file.get()) {
    LOG(ERROR) << "Unable to open '" << pdb_path.value() << "'";
    return false;
  }

  // Get the file size.
  uint32 file_size = 0;
  if (!GetFileSize(file.get(), &file_size)) {
    LOG(ERROR) << "Unable to determine size of '" << pdb_path.value() << "'";
    return false;
  }

  // Abuse the page reading function to read the header from the front of
  // the pdb file.
  PdbFileHeader header = {0};
  if (!ReadBytesFromPage(&header, file.get(), sizeof(header), 0, 1024)) {
    LOG(ERROR) << "Failed to read PDB file header";
    return false;
  }

  // Sanity check.
  if (header.num_pages * header.page_size != file_size) {
    LOG(ERROR) << "Invalid PDB file size";
    return false;
  }

  // Load the directory page list (a sequence of uint32 page numbers that is
  // itself written across multiple root pages). To do this we need to know how
  // many pages are required to represent the directory, then we load a stream
  // containing that many page pointers from the root pages array.
  uint32 num_dir_pages = GetNumPages(header.directory_size, header.page_size);
  scoped_array<uint32> dir_pages(new uint32[num_dir_pages]);
  if (dir_pages.get() == NULL) {
    LOG(ERROR) << "Failed to allocate root directory stream";
    return false;
  }
  uint32 dir_pages_size = num_dir_pages * sizeof(uint32);
  if (!LoadStream(dir_pages.get(),
                  file.get(),
                  dir_pages_size,
                  header.root_pages,
                  header.page_size)) {
    LOG(ERROR) << "Failed to read directory list";
    return false;
  }

  // Load the actual directory.
  scoped_array<uint32> directory(
      new uint32[header.directory_size / sizeof(uint32)]);
  if (!LoadStream(directory.get(),
                  file.get(),
                  header.directory_size,
                  dir_pages.get(),
                  header.page_size)) {
    LOG(ERROR) << "Failed to read directory stream";
    return false;
  }

  // Iterate through the streams
  const uint32& num_streams = directory[0];
  const uint32* stream_sizes = &(directory[1]);
  const uint32* stream_pages = &(directory[1 + num_streams]);
  uint32 page_index = 0;
  for (uint32 stream_index = 0; stream_index < num_streams; ++stream_index) {
    scoped_array<uint8> stream(new uint8[stream_sizes[stream_index]]);
    if (!LoadStream(stream.get(),
                    file.get(),
                    stream_sizes[stream_index],
                    stream_pages + page_index,
                    header.page_size)) {
      LOG(ERROR) << "Failed to extract stream #" << stream_index;
      return false;
    }
    pdb_streams->push_back(new PdbStream(stream.release(),
                                         stream_sizes[stream_index]));
    page_index += GetNumPages(stream_sizes[stream_index], header.page_size);
  }

  return true;
}

bool PdbReader::GetFileSize(FILE* file, uint32* size) {
  DCHECK(file != NULL);
  DCHECK(size != NULL);

  if (fseek(file, 0, SEEK_END) != 0) {
    LOG(ERROR) << "Failed seeking to end of file";
    return false;
  }

  long temp = ftell(file);
  if (temp == -1L) {
    LOG(ERROR) << "Failed to read stream position";
    return false;
  }

  (*size) = static_cast<uint32>(temp);
  return true;
}

bool PdbReader::ReadBytesFromPage(void* dest,
                                  FILE* file,
                                  uint32 num_bytes,
                                  uint32 page_num,
                                  uint32 page_size) {
  DCHECK(dest != NULL);
  DCHECK(file != NULL);
  DCHECK(page_size != 0);
  DCHECK(num_bytes <= page_size);

  uint32 offset = page_size * page_num;
  if (fseek(file, offset, SEEK_SET) != 0) {
    LOG(ERROR) << "Page seek failed";
    return false;
  }
  if (fread(dest, 1, num_bytes, file) != num_bytes) {
    LOG(ERROR) << "Page read failed";
    return false;
  }

  VLOG(1) << "Read page " << page_num << StringPrintf("(0x%08X)", offset);
  return true;
}

uint32 PdbReader::GetNumPages(uint32 num_bytes, uint32 page_size) {
  DCHECK(page_size > 0);
  return (num_bytes + page_size - 1) / page_size;
}

bool PdbReader::LoadStream(void* dest,
                           FILE* file,
                           uint32 num_bytes,
                           const uint32* const pages,
                           uint32 page_size) {
  DCHECK(dest != NULL);
  DCHECK(file != NULL);
  DCHECK(page_size != 0);
  DCHECK(pages != NULL);

  uint32 index = 0;
  while (num_bytes > 0) {
    uint32 chunk_size = std::min(page_size, num_bytes);
    if (!ReadBytesFromPage(dest, file, chunk_size, pages[index], page_size))
      return false;
    num_bytes -= chunk_size;
    index += 1;
    dest = reinterpret_cast<uint8*>(dest) + chunk_size;
  }

  return true;
}
