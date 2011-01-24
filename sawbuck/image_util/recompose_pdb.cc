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
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/string_util.h"
#include <iostream>

namespace {

// This is the Multi-Stream Format (MSF) page size generally used for PDB
// files.  Check bytes 32 through 35 (little endian) of any PDB file.
const uint32 kPageSize = 1024;

// The maximum number of root pages in the Multi-Stream Format (MSF) header.
// See http://code.google.com/p/pdbparser/wiki/MSF_Format
const uint32 kMaxRootPages = 0x49;

// This is an array of nul-bytes used as a source when writing padding bytes.
const uint8 kZeroBuffer[kPageSize] = {0};

// Used to capture the size and offset of a stream after it's been appended
// to the recomposed PDB file.
struct StreamInfoRecord {
  // The byte offset at which the stream is written into the output file.
  // This is always a multiple of kPageSize.
  uint32 offset;

  // The size (in bytes) of the stream.
  uint32 size;
};

// Container for all the stream sizes and offsets in the reconstituted
// PDB file.
typedef std::vector<StreamInfoRecord> StreamInfo;

// This is the magic value found at the start of all MSF v7.00 files.
const uint8 MSF_HEADER_MAGIC[] = {
  0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, // "Microsof"
  0x74, 0x20, 0x43, 0x2F, 0x43, 0x2B, 0x2B, 0x20, // "t C/C++ "
  0x4D, 0x53, 0x46, 0x20, 0x37, 0x2E, 0x30, 0x30, // "MSF 7.00"
  0x0D, 0x0A, 0x1A, 0x44, 0x53, 0x00, 0x00, 0x00  // "^^^DS^^^"
};

// Write an unsigned 32 bit value to the output file.
//
// @param func The name of the calling function (logged on failure).
// @param desc The description of the value being written (logged on failure).
// @param file The handle to the output file stream.
// @param value The value to be written.
bool WriteUint32(const char* func,
                 const char* desc,
                 FILE* file,
                 uint32 value) {
  DCHECK(func != NULL);
  DCHECK(desc != NULL);
  DCHECK(file != NULL);

  if (fwrite(&value, sizeof(value), 1, file) != 1) {
    LOG(ERROR) << func << ": Failed writing " << desc;
    return false;
  }

  return true;
}

// Pads the current page to reach the next page boundary.
//
// @param func The name of the calling function (logged on failure).
// @param file The output file handle to which the padding will be written.
// @param current_offset The offset from the start of the current or any
//     previous page which will be used to calculate the offset of the next
//     page boundary.
// @param bytes_written The number of padding bytes written will be returned
//     here.
bool PadToPageBoundary(const char* func,
                       FILE* file,
                       uint32 current_offset,
                       uint32* bytes_written) {
  DCHECK(func != NULL);
  DCHECK(file != NULL);
  DCHECK(bytes_written != NULL);

  size_t padding = (kPageSize - (current_offset % kPageSize)) % kPageSize;
  if (padding != 0) {
    if (fwrite(kZeroBuffer, 1, padding, file) != padding) {
      LOG(ERROR) << func << ": Failed padding to page boundary";
      return false;
    }
  }

  (*bytes_written) = static_cast<uint32>(padding);
  return true;
}

// Appends the contents of the file given by the source path onto the
// (already opened for writing) out_file handle.  The contents of the
// file are padded to reach the next page boundary in the output stream.
// Information about the stream (source, size, etc) are added to the
// stream_info structure.
//
// @param out_file  The handle to the output file stream
// @param start_offset  The current offset into the output file.  Note that
//     the function assumes this is being tracked elsewhere and is purely
//     informational; it does not seek to this offset before writing.
// @param source  The path to the input stream file.
// @param record  The start offset and size of the stream will be recorded
//     to this structure.
// @param bytes_written The total number or bytes written (including padding)
//     will be recorded here.
bool AppendStream(FILE* out_file,
                  uint32 start_offset,
                  const FilePath& source,
                  StreamInfoRecord* record,
                  uint32* bytes_written) {
  DCHECK(record != NULL);
  DCHECK(bytes_written != NULL);
  DCHECK(start_offset % kPageSize == 0);

  file_util::ScopedFILE in_file(file_util::OpenFile(source, "rb"));
  if (!in_file.get()) {
    LOG(ERROR) << "Failed to open " << source.value();
    return false;
  }

  // The counter to track the number of bytes written (for this stream).
  uint32 stream_size = 0;

  // Append the contents of source to out_file (in 64K chuncks).
  char buf[1 << 16];
  size_t chunk_size = 0;
  while ((chunk_size = fread(buf, 1, sizeof(buf), in_file.get())) > 0) {
    if (fwrite(buf, 1, chunk_size, out_file) != chunk_size) {
      LOG(ERROR) << "Error appending to output file!";
      return false;
    }
    stream_size += chunk_size;
  }

  // Check for read failure.
  if (ferror(in_file.get())) {
    LOG(ERROR) << "Error reading from " << source.value();
    return false;
  }

  // We should be at the end of the file.
  if (!feof(in_file.get())) {
    LOG(ERROR) << "Reached invalid state reading " << source.value();
    return false;
  }

  // Pad to a page boundary.
  uint32 padding = 0;
  if (!PadToPageBoundary("AppendStream", out_file, stream_size, &padding))
    return false;

  // Capture the stream details in the output variables.
  record->offset = start_offset;
  record->size = stream_size;
  (*bytes_written) = stream_size + padding;

  DCHECK((*bytes_written) % kPageSize == 0);

  return true;
}

// Enumerates over the files matching the prefix pattern and tacks them
// on, one after the other, padded to page boundaries, to the (already
// opened for writing) out_file handle.  Details about each stream will
// be added to the stream_info_map.
//
// @param file The handle to the output file stream.
// @param start_offset The current offset into the output file.
// @param prefix The pattern from which the input stream file paths are
//     derived.
// @param stream_info The start offset and size of the stream will be
//     recorded here.
// @param bytes_written The total number or bytes written (including
//     padding) will be recorded here.
bool ConcatStreams(FILE* file,
                   uint32 start_offset,
                   const FilePath& prefix,
                   StreamInfo* stream_info,
                   size_t* bytes_written) {
  DCHECK(bytes_written != NULL);
  DCHECK(stream_info->empty());

  // Enumerate all files matching prefix.???
  // @note The windows file matching for foo.??? will return foo, which kinda
  //     sucks.  It means you can't have your original zzz.pdb file in the
  //     same dir as zzz.pdb.000 when running this tool.
  // TODO(rogerm): weed out (ignore?) bad matches returned by the enumerator
  uint32 byte_count = 0;
  uint32 current_offset = start_offset;
  file_util::FileEnumerator enumerator(prefix.DirName(),
                                       false,  // non-recursive
                                       file_util::FileEnumerator::FILES,
                                       prefix.BaseName().value() + L".???");
  FilePath path = enumerator.Next();
  for (uint32 i = 0; !path.empty(); ++i, path = enumerator.Next()) {
    // Make sure we get all the streams in numerical order.
    if (path.Extension() != StringPrintf(L".%03d", i)) {
      LOG(ERROR) << "Stream #" << i << " is missing!";
      return false;
    }

    VLOG(1) << "Adding: " << path.value();

    // Append the stream and record it's details.
    StreamInfoRecord record;
    uint32 length = 0;
    if (!AppendStream(file, current_offset, path, &record, &length)) {
      return false;
    }
    stream_info->push_back(record);

    byte_count += length;
    current_offset += length;
  }

  (*bytes_written) = byte_count;

  DCHECK((*bytes_written) % kPageSize == 0);

  return true;
}

// Given the stream_info, writes the set of directory pages to the
// (already opened for writing) out_file handle.
//
// @param file The handle to the output file stream.
// @param stream_info All the stream offsets and sizes.
// @directory_length The byte length of the directory structure will be
//     returned here.
// @bytes_written The total number of bytes (including padding) written
//     to the file.
bool WriteDirectory(FILE* file,
                    const StreamInfo& stream_info,
                    uint32* directory_length,
                    uint32* bytes_written) {
  static const char * const func = "WriteDirectory";

  DCHECK(file != NULL);
  DCHECK(directory_length != NULL);
  DCHECK(bytes_written != NULL);

  VLOG(1) << "Writing directory ...";

  // The directory format is:
  //    num_streams   (32-bit)
  //    + stream_length (32-bit) for each stream in num_streams
  //    + page_offset   (32-bit) for each page in each stream in num_streams

  uint32 byte_count = 0;

  // Write the number of streams.
  if (!WriteUint32(func, "stream count", file, stream_info.size()))
    return false;
  byte_count += sizeof(uint32);

  // Write the size of each stream.
  for (StreamInfo::const_iterator iter = stream_info.begin();
       iter != stream_info.end();
       ++iter) {
    if (!WriteUint32(func, "stream size", file, iter->size))
      return false;
    byte_count += sizeof(uint32);
  }

  // Write the page numbers for each page in each stream.
  for (StreamInfo::const_iterator iter = stream_info.begin();
       iter != stream_info.end();
       ++iter) {
    DCHECK(iter->offset % kPageSize == 0);
    uint32 page_number = iter->offset / kPageSize;
    for (uint32 size = 0; size < iter->size; size += kPageSize) {
      if (!WriteUint32(func, "page offset", file, page_number))
        return false;
      byte_count += sizeof(uint32);
      page_number += 1;
    }
  }

  // Pad the directory to the next page boundary.
  uint32 padding_length = 0;
  if (!PadToPageBoundary(func, file, byte_count, &padding_length))
    return false;

  // Return the output values
  (*directory_length) = byte_count;
  (*bytes_written) = byte_count + padding_length;

  DCHECK((*bytes_written) % kPageSize == 0);

  return true;
}

// Writes the list of root pages which form the MSF directory.
//
// @param file The handle to the output file stream.
// @param start_page The first page on which the directory is written.
// @param dir_size The number of bytes consumed by the directory.
// @param dir_map_size The numberr of bytes used to represent the directory
//     map will be returned here.
// @param bytes_written The total number of bytes (inluding padding) taken
//     by the directory map will be returned here.
bool WriteDirectoryRoots(FILE* file,
                         uint32 start_page,
                         uint32 dir_size,
                         uint32* dir_map_size,
                         uint32* bytes_written) {
  static const char * const func = "WriteDirectoryRoots";

  VLOG(1) << "Writing directory roots...";

  DCHECK(file != NULL);
  DCHECK(dir_map_size != NULL);
  DCHECK(bytes_written != NULL);

  // Write all page offsets that are used in the directory.
  uint32 len = 0;
  for (uint32 page_offset = 0, dir_page = start_page;
       page_offset < dir_size;
       page_offset += kPageSize, ++dir_page) {
    if (!WriteUint32(func, "page offset", file, dir_page))
      return false;
    len += sizeof(uint32);
  }

  // Pad to a page boundary.
  uint32 padding = 0;
  if (!PadToPageBoundary(func, file, len, &padding))
    return false;

  (*dir_map_size) = len;
  (*bytes_written) = len + padding;

  DCHECK((*bytes_written) % kPageSize == 0);

  return true;
}

// Writes the MSF/PDB file header once you know where the directory root
// pages are and what the directory size and the total size of the file are.
//
// @param file The handle to the output file stream.
// @param dir_root_page The first page on which the directory root pages are
//     written.
// @param dir_root_size The number of bytes used to represent the directory
//     roots
// @param dir_size The number of bytes consumed by the directory.
// @param file_size The total number of bytes in the output stream.
bool WriteHeader(FILE* file,
                 size_t dir_root_page,
                 size_t dir_root_size,
                 size_t dir_size,
                 size_t file_size) {
  static const char* const func = "WriteHeader";

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

// Builds a PDB file given a prefix and an output file name.  All numbered
// files matching the pattern <prefix>.NNN, where NNN counts up (in decimal)
// from 000, will be inserted into the generated output file, given by
// output.
//
// @param prefix The path prefix for the input stream files.
// @param output The path to the output file.
bool AssemblePDB(const FilePath& prefix, const FilePath& output) {
  file_util::ScopedFILE out_file(file_util::OpenFile(output, "wb"));
  if (!out_file.get()) {
    LOG(ERROR) << "Failed to create " << output.value();
    return false;
  }

  uint32 total_bytes = 0;

  // Reserve space for the header and free page map.
  // TODO(rogerm): The free page map is a kludge.  This should be sized to
  //     correspond to the file instead of just one page.  It should be
  //     relocated to the end and sized properly.
  if (fseek(out_file.get(), kPageSize * 3, SEEK_SET) != 0) {
    LOG(ERROR) << "Failed to reserve header and free page map";
    return false;
  }
  total_bytes += (kPageSize * 3);

  // Concatenate all the input streams after the header, remembering their
  // sizes.
  StreamInfo stream_info;
  uint32 bytes_written = 0;
  if (!ConcatStreams(out_file.get(),
                     total_bytes,
                     prefix,
                     &stream_info,
                     &bytes_written))
    return false;
  total_bytes += bytes_written;

  DCHECK((bytes_written % kPageSize) == 0);
  DCHECK((total_bytes % kPageSize) == 0);

  // Map out the directory: i.e., pages on which the streams have been written.
  uint32 dir_page = (total_bytes / kPageSize);
  uint32 dir_size = 0;
  if (!WriteDirectory(out_file.get(), stream_info, &dir_size, &bytes_written))
    return false;
  total_bytes += bytes_written;

  // Map out the directory roots: i.e., pages on which the directory has been
  // written.
  uint32 dir_root_page = (total_bytes / kPageSize);
  uint32 dir_root_size = 0;
  if (!WriteDirectoryRoots(out_file.get(),
                           dir_page,
                           dir_size,
                           &dir_root_size,
                           &bytes_written))
    return false;
  total_bytes += bytes_written;

  // Fill in the MSF header.
  if (!WriteHeader(out_file.get(),
                   dir_root_page,
                   dir_root_size,
                   dir_size,
                   total_bytes))
    return false;

  return true;
}

// Prints usage information, with an optional message.
int Usage(char** argv, const char* message) {
  if (message != NULL) {
    std::cout << message << std::endl << std::endl;
  }

  std::cout <<
      "Usage: " << argv[0] << " [options]" << std::endl;
  std::cout <<
      "  This tool takes a numbered set of input files and assembles them\n"
      "  into a multi-stream format PDB file.\n"
      "\n"
      "Available options\n"
      "  --input=<pdb-file-prefix>\n"
      "      The streams of the PDB file will be <pdb-file-prefix>.NNN\n"
      "  --output=<file-path>\n"
      "      The name of the output PDB file to generate.\n";

  return 1;
}

} // unnamed namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  CommandLine::Init(argc, argv);

  if (!logging::InitLogging(L"",
                            logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
                            logging::DONT_LOCK_LOG_FILE,
                            logging::APPEND_TO_OLD_LOG_FILE)) {
    std::cerr << "Failed to initialize logging!" << std::endl;
    return 1;
  }

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  DCHECK(cmd_line != NULL);

  std::wstring prefix = cmd_line->GetSwitchValueNative("input");
  if (prefix.empty())
    return Usage(argv, "You must provide the pdb input file prefix.");

  std::wstring output = cmd_line->GetSwitchValueNative("output");
  if (output.empty())
    return Usage(argv, "You must provide the pdb output file name.");

  if (!AssemblePDB(FilePath(prefix), FilePath(output))) {
    std::cerr << "Failed to construct PDB file, check the logs" << std::endl;
    return 1;
  }

  std::cout << "Ok" << std::endl;
  return 0;
}
