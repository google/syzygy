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

#include "sawbuck/image_util/pdb_writer.h"

#include "base/file_util.h"
#include "base/logging.h"

// This is the Multi-Stream Format (MSF) page size generally used for PDB
// files.  Check bytes 32 through 35 (little endian) of any PDB file.
const uint32 kPageSize = 1024;

// The maximum number of root pages in the Multi-Stream Format (MSF) header.
// See http://code.google.com/p/pdbparser/wiki/MSF_Format
const uint32 kMaxRootPages = 0x49;

// This is an array of nul-bytes used as a source when writing padding bytes.
const uint8 kZeroBuffer[kPageSize] = {0};

// This is the magic value found at the start of all MSF v7.00 files.
const uint8 MSF_HEADER_MAGIC[] = {
  0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, // "Microsof"
  0x74, 0x20, 0x43, 0x2F, 0x43, 0x2B, 0x2B, 0x20, // "t C/C++ "
  0x4D, 0x53, 0x46, 0x20, 0x37, 0x2E, 0x30, 0x30, // "MSF 7.00"
  0x0D, 0x0A, 0x1A, 0x44, 0x53, 0x00, 0x00, 0x00  // "^^^DS^^^"
};

PdbWriter::PdbWriter() {
}

PdbWriter::~PdbWriter() {
}

bool PdbWriter::Write(const FilePath& pdb_path,
                      const PdbStreamList& pdb_streams) {
  file_util::ScopedFILE file(file_util::OpenFile(pdb_path, "wb"));
  if (!file.get()) {
    LOG(ERROR) << "Failed to create " << pdb_path.value();
    return false;
  }

  uint32 total_bytes = 0;

  // Reserve space for the header and free page map.
  // TODO(rogerm): The free page map is a kludge. This should be sized to
  // correspond to the file instead of just one page. It should be relocated
  // to the end and sized properly.
  if (fseek(file.get(), kPageSize * 3, SEEK_SET) != 0) {
    LOG(ERROR) << "Failed to reserve header and free page map";
    return false;
  }
  total_bytes += kPageSize * 3;

  // Append all the streams after the header.
  StreamInfoList stream_info_list;
  for (PdbStreamList::const_iterator iter = pdb_streams.begin();
      iter != pdb_streams.end(); iter++) {
    uint32 bytes_written = 0;
    if (!AppendStream(file.get(),
                      *iter,
                      &bytes_written))
      return false;

    StreamInfo info = {total_bytes, (*iter)->size()};
    stream_info_list.push_back(info);

    total_bytes += bytes_written;
    DCHECK((total_bytes % kPageSize) == 0);
  }

  // Map out the directory: i.e., pages on which the streams have been written.
  uint32 dir_page = (total_bytes / kPageSize);
  uint32 dir_size = 0;
  uint32 bytes_written = 0;
  if (!WriteDirectory(file.get(), stream_info_list, &dir_size, &bytes_written))
    return false;
  total_bytes += bytes_written;

  // Map out the directory roots: i.e., pages on which the directory has been
  // written.
  uint32 dir_root_page = (total_bytes / kPageSize);
  uint32 dir_root_size = 0;
  if (!WriteDirectoryPages(file.get(),
                           dir_page,
                           dir_size,
                           &dir_root_size,
                           &bytes_written))
    return false;
  total_bytes += bytes_written;

  // Fill in the MSF header.
  if (!WriteHeader(file.get(),
                   dir_root_page,
                   dir_root_size,
                   dir_size,
                   total_bytes))
    return false;

  return true;
}

// Write an unsigned 32 bit value to the output file.
bool PdbWriter::WriteUint32(const char* func,
                            const char* desc,
                            FILE* file,
                            uint32 value) {
  DCHECK(func != NULL);
  DCHECK(desc != NULL);
  DCHECK(file != NULL);

  if (fwrite(&value, sizeof(value), 1, file) != 1) {
    LOG(ERROR) << func << ": Error writing " << desc;
    return false;
  }

  return true;
}

bool PdbWriter::PadToPageBoundary(const char* func,
                                  FILE* file,
                                  uint32 offset,
                                  uint32* padding) {
  DCHECK(file != NULL);
  DCHECK(padding != NULL);

  *padding = (kPageSize - (offset % kPageSize)) % kPageSize;
  if (fwrite(kZeroBuffer, 1, *padding, file) != *padding) {
    LOG(ERROR) << func << ": Error padding page";
    return false;
  }

  return true;
}

bool PdbWriter::AppendStream(FILE* file,
                             const PdbStream* pdb_stream,
                             uint32* bytes_written) {
  DCHECK(file != NULL);
  DCHECK(bytes_written != NULL);

  // Append the contents of source to output file.
  if (fwrite(pdb_stream->stream(), 1, pdb_stream->size(), file) !=
      pdb_stream->size()) {
    LOG(ERROR) << "Error appending stream to file";
    return false;
  }

  // Pad to the end of the current page boundary.
  uint32 padding = 0;
  if (!PadToPageBoundary("AppendStream", file, pdb_stream->size(), &padding))
    return false;

  *bytes_written = pdb_stream->size() + padding;
  DCHECK((*bytes_written) % kPageSize == 0);

  return true;
}

bool PdbWriter::WriteDirectory(FILE* file,
                               const StreamInfoList& stream_info_list,
                               uint32* directory_size,
                               uint32* bytes_written) {
  static const char * func = "WriteDirectory";

  DCHECK(file != NULL);
  DCHECK(directory_size != NULL);
  DCHECK(bytes_written != NULL);

  VLOG(1) << "Writing directory ...";

  // The directory format is:
  //    num_streams   (32-bit)
  //    + stream_length (32-bit) for each stream in num_streams
  //    + page_offset   (32-bit) for each page in each stream in num_streams

  uint32 byte_count = 0;

  // Write the number of streams.
  if (!WriteUint32(func, "stream count", file, stream_info_list.size()))
    return false;
  byte_count += sizeof(uint32);

  // Write the size of each stream.
  for (StreamInfoList::const_iterator iter = stream_info_list.begin();
       iter != stream_info_list.end(); ++iter) {
    if (!WriteUint32(func, "stream size", file, iter->size))
      return false;
    byte_count += sizeof(uint32);
  }

  // Write the page numbers for each page in each stream.
  for (StreamInfoList::const_iterator iter = stream_info_list.begin();
       iter != stream_info_list.end(); ++iter) {
    DCHECK(iter->offset % kPageSize == 0);
    for (uint32 size = 0, page_number = iter->offset / kPageSize;
         size < iter->size;
         size += kPageSize, ++page_number) {
      if (!WriteUint32(func, "page offset", file, page_number))
        return false;
      byte_count += sizeof(uint32);
    }
  }

  // Pad the directory to the next page boundary.
  uint32 padding = 0;
  if (!PadToPageBoundary(func, file, byte_count, &padding))
    return false;

  // Return the output values
  (*directory_size) = byte_count;
  (*bytes_written) = byte_count + padding;

  DCHECK((*bytes_written) % kPageSize == 0);
  return true;
}

bool PdbWriter::WriteDirectoryPages(FILE* file,
                                    uint32 start_page,
                                    uint32 dir_size,
                                    uint32* dir_pages_size,
                                    uint32* bytes_written) {
  static const char * func = "WriteDirectoryPages";

  VLOG(1) << "Writing directory roots...";

  DCHECK(file != NULL);
  DCHECK(dir_pages_size != NULL);
  DCHECK(bytes_written != NULL);

  // Write all page offsets that are used in the directory.
  uint32 byte_count = 0;
  for (uint32 page_offset = 0, dir_page = start_page;
       page_offset < dir_size;
       page_offset += kPageSize, ++dir_page) {
    if (!WriteUint32(func, "page offset", file, dir_page))
      return false;
    byte_count += sizeof(uint32);
  }

  // Pad to a page boundary.
  uint32 padding = 0;
  if (!PadToPageBoundary(func, file, byte_count, &padding))
    return false;

  (*dir_pages_size) = byte_count;
  (*bytes_written) = byte_count + padding;

  DCHECK((*bytes_written) % kPageSize == 0);

  return true;
}

bool PdbWriter::WriteHeader(FILE* file,
                            size_t dir_root_page,
                            size_t dir_root_size,
                            size_t dir_size,
                            size_t file_size) {
  static const char* func = "WriteHeader";

  DCHECK(file != NULL);
  DCHECK(file_size % kPageSize == 0);

  VLOG(1) << "Writing MSF Header ...";

  if (fseek(file, 0, SEEK_SET) != 0) {
    LOG(ERROR) << "Seek failed when writing header";
    return false;
  }

  if (fwrite(MSF_HEADER_MAGIC, sizeof(MSF_HEADER_MAGIC), 1, file) != 1) {
    LOG(ERROR) << "Failed writing magic string";
    return false;
  }

  if (!WriteUint32(func, "page size", file, kPageSize))
    return false;

  if (!WriteUint32(func, "free page map", file, 1))
    return false;

  if (!WriteUint32(func, "page count", file, file_size / kPageSize))
    return false;

  if (!WriteUint32(func, "directory size", file, dir_size))
    return false;

  if (!WriteUint32(func, "reserved flag", file, 0))
    return false;

  // Make sure the root pages list won't overflow
  if ((dir_root_size + kPageSize - 1) / kPageSize > kMaxRootPages) {
    LOG(ERROR) << "Too many directory root pages!";
    return false;
  }

  for (size_t page_offset = 0;
       page_offset < dir_root_size;
       page_offset += kPageSize, ++dir_root_page) {
    if (!WriteUint32(func, "root page", file, dir_root_page))
      return false;
  }

  return true;
}
