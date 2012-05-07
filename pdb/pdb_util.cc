// Copyright 2012 Google Inc.
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
#include "syzygy/pdb/pdb_util.h"

#include <algorithm>
#include "sawbuck/common/buffer_parser.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_writer.h"

namespace pdb {

namespace {

bool ReadString(PdbStream* stream, std::string* out) {
  DCHECK(out != NULL);

  std::string result;
  char c = 0;
  while (stream->Read(&c, 1)) {
    if (c == '\0') {
      out->swap(result);
      return true;
    }
    result.push_back(c);
  }

  return false;
}

bool ReadStringAt(PdbStream* stream, size_t pos, std::string* out) {
  size_t save = stream->pos();
  bool read = stream->Seek(pos) && ReadString(stream, out);
  stream->Seek(save);
  return read;
}

}  // namespace

bool PdbBitSet::Read(PdbStream* stream) {
  DCHECK(stream != NULL);
  uint32 size = 0;
  if (!stream->Read(&size, 1)) {
    LOG(ERROR) << "Failed to read bitset size.";
    return false;
  }
  if (!stream->Read(&bits_, size)) {
    LOG(ERROR) << "Failed to read bitset bits.";
    return false;
  }

  return true;
}

bool PdbBitSet::Write(WritablePdbStream* stream) {
  DCHECK(stream != NULL);
  if (!stream->Write(static_cast<uint32>(bits_.size()))) {
    LOG(ERROR) << "Failed to write bitset size.";
    return false;
  }
  if (bits_.size() == 0)
    return true;
  if (!stream->Write(bits_.size(), &bits_[0])) {
    LOG(ERROR) << "Failed to write bitset bits.";
    return false;
  }

  return true;
}

void PdbBitSet::Resize(size_t bits) {
  bits_.resize((bits + 31) / 32);
}

void PdbBitSet::Set(size_t bit) {
  size_t index = bit / 32;
  if (index >= bits_.size())
    return;
  bits_[index] |= (1 << (bit % 32));
}

void PdbBitSet::Clear(size_t bit) {
  size_t index = bit / 32;
  if (index >= bits_.size())
    return;
  bits_[index] &= ~(1 << (bit % 32));
}

void PdbBitSet::Toggle(size_t bit) {
  size_t index = bit / 32;
  if (index >= bits_.size())
    return;
  bits_[index] ^= (1 << (bit % 32));
}

bool PdbBitSet::IsSet(size_t bit) const {
  size_t index = bit / 32;
  if (index >= bits_.size())
    return false;

  return (bits_[index] & (1 << (bit % 32))) != 0;
}

bool PdbBitSet::IsEmpty() const {
  return bits_.size() == 0;
}

uint32 GetDbiDbgHeaderOffset(const DbiHeader& dbi_header) {
  uint32 offset = sizeof(DbiHeader);
  offset += dbi_header.gp_modi_size;
  offset += dbi_header.section_contribution_size;
  offset += dbi_header.section_map_size;
  offset += dbi_header.file_info_size;
  offset += dbi_header.ts_map_size;
  offset += dbi_header.ec_info_size;  // Unexpected, but necessary.
  return offset;
}

bool AddOmapStreamToPdbFile(const FilePath& input_file,
                            const FilePath& output_file,
                            const GUID& output_guid,
                            const std::vector<OMAP>& omap_to_list,
                            const std::vector<OMAP>& omap_from_list) {
  // Read the input Pdb's streams.
  PdbReader reader;
  PdbFile pdb_file;
  if (!reader.Read(input_file, &pdb_file)) {
    LOG(ERROR) << "Failed to read '" << input_file.value() << "'";
    return false;
  }

  // TODO(chrisha): Once the WritablePdbStream interface is in place,
  //     make a PdbFile::MakeStreamWritable member function that will ensure
  //     a stream is in a writable format (in memory). Copying and transfer
  //     of ownership will disappear as the streams are made reference counted.

  // Copy the Dbi stream into memory and overwrite it in the stream list.
  scoped_refptr<PdbByteStream> new_dbi_stream(new PdbByteStream);
  PdbByteStream* dbi_stream = new_dbi_stream.get();
  if (pdb_file.StreamCount() <= kDbiStream ||
      !dbi_stream->Init(pdb_file.GetStream(kDbiStream))) {
    LOG(ERROR) << "Failed to initialize Dbi byte stream";
    return false;
  }

  // We explicitly transfer ownership to the PDB file.
  pdb_file.ReplaceStream(kDbiStream, new_dbi_stream.release());

  // Copy the Pdb header info stream into memory and adjust the header info.
  scoped_refptr<PdbByteStream> new_pdb_info_stream(new PdbByteStream);
  PdbByteStream* pdb_info_stream = new_pdb_info_stream.get();
  if (pdb_file.StreamCount() <= kPdbHeaderInfoStream ||
      !pdb_info_stream->Init(pdb_file.GetStream(kPdbHeaderInfoStream))) {
    LOG(ERROR) << "Failed to initialize Pdb info byte stream";
    return false;
  }

  if (pdb_info_stream->length() < sizeof(PdbInfoHeader70)) {
    LOG(ERROR) << "Pdb info stream too short";
    return false;
  }

  PdbInfoHeader70* info_header =
      reinterpret_cast<PdbInfoHeader70*>(pdb_info_stream->data());
  info_header->timetamp = static_cast<uint32>(time(NULL));
  // Reset age to 1, as this is a new generation.
  info_header->pdb_age = 1;
  info_header->signature = output_guid;

  // We explicitly transfer ownership to the PDB file.
  pdb_file.ReplaceStream(kPdbHeaderInfoStream, new_pdb_info_stream.release());

  // Read the Dbi header.
  DbiHeader dbi_header;
  if (dbi_stream->Read(&dbi_header, 1) != 1) {
    LOG(ERROR) << "Failed to read Dbi header";
    return false;
  }

  // Point the Dbi debug header into the existing byte stream.
  BinaryBufferParser parser(dbi_stream->data(), dbi_stream->length());
  uint32 offset = GetDbiDbgHeaderOffset(dbi_header);
  DbiDbgHeader* dbi_dbg_header;
  if (!parser.GetAt(offset,
                    const_cast<const DbiDbgHeader**>(&dbi_dbg_header))) {
    LOG(ERROR) << "Failed to get Dbi dbg header stream pointer";
  }

  // Create the Omap to stream.
  scoped_refptr<PdbByteStream> omap_to_stream(new PdbByteStream);
  if (!omap_to_stream->Init(
      reinterpret_cast<const uint8*>(&omap_to_list.at(0)),
      omap_to_list.size() * sizeof(OMAP))) {
    LOG(ERROR) << "Failed to initialize Omap to byte stream";
    return false;
  }
  // Add the new stream and update the Dbi debug header, or overwrite the stream
  // it if it already exists.
  if (dbi_dbg_header->omap_to_src == -1) {
    size_t omap_to_index = pdb_file.AppendStream(omap_to_stream.release());
    dbi_dbg_header->omap_to_src = omap_to_index;
  } else {
    pdb_file.ReplaceStream(dbi_dbg_header->omap_to_src,
                           omap_to_stream.release());
  }

  // Create the Omap from stream.
  scoped_refptr<PdbByteStream> omap_from_stream(new PdbByteStream);
  if (!omap_from_stream->Init(
      reinterpret_cast<const uint8*>(&omap_from_list.at(0)),
      omap_from_list.size() * sizeof(OMAP))) {
    LOG(ERROR) << "Failed to initialize Omap to byte stream";
    return false;
  }
  // Add the new stream and update the Dbi debug header, or overwrite the stream
  // it if it already exists.
  if (dbi_dbg_header->omap_from_src == -1) {
    size_t omap_from_index = pdb_file.AppendStream(omap_from_stream.release());
    dbi_dbg_header->omap_from_src = omap_from_index;
  } else {
    pdb_file.ReplaceStream(dbi_dbg_header->omap_from_src,
                           omap_from_stream.release());
  }

  // Write the new Pdb file.
  PdbWriter writer;
  if (!writer.Write(output_file, pdb_file)) {
    LOG(ERROR) << "Failed to write '" << output_file.value() << "'";
    return false;
  }

  return true;
}

bool ReadPdbHeader(const FilePath& pdb_path, PdbInfoHeader70* pdb_header) {
  DCHECK(!pdb_path.empty());
  DCHECK(pdb_header != NULL);

  PdbReader pdb_reader;
  PdbFile pdb_file;
  if (!pdb_reader.Read(pdb_path, &pdb_file)) {
    LOG(ERROR) << "Unable to process PDB file: " << pdb_path.value();
    return false;
  }

  PdbStream* header_stream = pdb_file.GetStream(kPdbHeaderInfoStream);
  if (header_stream == NULL) {
    LOG(ERROR) << "PDB file contains no header stream: " << pdb_path.value();
    return false;
  }

  if (!header_stream->Read(pdb_header, 1)) {
    LOG(ERROR) << "Failure reading PDB header: " << pdb_path.value();
    return false;
  }

  // We only know how to deal with PDB files of the current version.
  if (pdb_header->version != kPdbCurrentVersion) {
    LOG(ERROR) << "PDB header has unsupported version (got "
               << pdb_header->version << ", expected " << kPdbCurrentVersion
               << ").";
    return false;
  }

  return true;
}

bool ReadHeaderInfoStream(PdbStream* pdb_stream,
                          PdbInfoHeader70* pdb_header,
                          NameStreamMap* name_stream_map) {
  VLOG(1) << "Header Info Stream size: " << pdb_stream->length();

  // The header stream starts with the fixed-size header pdb_header record.
  if (!pdb_stream->Read(pdb_header, 1)) {
    LOG(ERROR) << "Unable to read PDB pdb_header header.";
    return false;
  }

  uint32 string_len = 0;
  if (!pdb_stream->Read(&string_len, 1)) {
    LOG(ERROR) << "Unable to read string table length.";
    return false;
  }

  // The fixed-size record is followed by information on named streams, which
  // is essentially a string->id mapping. This starts with the strings
  // themselves, which have been observed to be a packed run of zero-terminated
  // strings.
  // We store the start of the string list, as the string positions we read
  // later are relative to that position.
  size_t string_start = pdb_stream->pos();

  // Seek past the strings.
  if (!pdb_stream->Seek(string_start + string_len)) {
    LOG(ERROR) << "Unable to seek past string list";
    return false;
  }

  // Next there's a pair of integers. The first one of those is the number of
  // items in the string->id mapping. The purpose of the second one is not
  // clear, but has been observed as larger or equal to the first one.
  uint32 size = 0;
  uint32 max = 0;
  if (!pdb_stream->Read(&size, 1) || !pdb_stream->Read(&max, 1)) {
    LOG(ERROR) << "Unable to read name pdb_stream size/max";
    return false;
  }
  DCHECK(max >= size);

  // After the counts, there's a pair of bitsets. Each bitset has a 32 bit
  // length, followed by that number of 32 bit words that contain the bits.
  // The purpose of those is again not clear, though the first set will have
  // "size" bits of the bits in the range 0-max set.
  PdbBitSet used;
  PdbBitSet deleted;
  if (!used.Read(pdb_stream) || !deleted.Read(pdb_stream)) {
    LOG(ERROR) << "Unable to read name pdb_stream bitsets.";
    return false;
  }

#ifndef NDEBUG
  // The first bitset has "size" bits set of the first "max" bits.
  size_t set_bits = 0;
  for (size_t i = 0; i < max; ++i) {
    if (used.IsSet(i))
      ++set_bits;
  }

  // The second bitset has always been observed to be empty.
  DCHECK(deleted.IsEmpty());

  DCHECK_EQ(size, set_bits);
#endif

  // Read the mapping proper, this is simply a run of {string offset, id} pairs.
  for (size_t i = 0; i < size; ++i) {
    uint32 str_offs = 0;
    uint32 stream_no = 0;
    // Read the offset and pdb_stream number.
    if (!pdb_stream->Read(&str_offs, 1) || !pdb_stream->Read(&stream_no, 1)) {
      LOG(ERROR) << "Unable to read pdb_stream data.";
      return false;
    }

    // Read the string itself from the table.
    std::string name;
    if (!ReadStringAt(pdb_stream, string_start + str_offs, &name)) {
      LOG(ERROR) << "Failed to read pdb_stream name.";
      return false;
    }

    (*name_stream_map)[name] = stream_no;
  }

  return true;
}

bool WriteHeaderInfoStream(const PdbInfoHeader70& pdb_header,
                           const NameStreamMap& name_stream_map,
                           WritablePdbStream* pdb_stream) {
  DCHECK(pdb_stream != NULL);

  if (!pdb_stream->Write(pdb_header)) {
    LOG(ERROR) << "Failed to write PDB header.";
    return false;
  }

  // Get the string table length.
  std::vector<uint32> offsets;
  offsets.reserve(name_stream_map.size());
  uint32 string_length = 0;
  NameStreamMap::const_iterator name_it = name_stream_map.begin();
  for (; name_it != name_stream_map.end(); ++name_it) {
    offsets.push_back(string_length);
    string_length += name_it->first.size() + 1;  // Include the trailing zero.
  }

  // Dump the string table.
  if (!pdb_stream->Write(string_length)) {
    LOG(ERROR) << "Failed to write stream name table length.";
    return false;
  }
  name_it = name_stream_map.begin();
  for (; name_it != name_stream_map.end(); ++name_it) {
    if (!pdb_stream->Write(name_it->first.size() + 1, name_it->first.c_str())) {
      LOG(ERROR) << "Failed to write stream name.";
      return false;
    }
  }

  // Write the string table size. We write the value twice, and use the smallest
  // possible bitset. See ReadHeaderInfoStream for a detailed discussion of the
  // layout.
  const uint32 kStringCount = name_stream_map.size();
  if (!pdb_stream->Write(kStringCount) || !pdb_stream->Write(kStringCount)) {
    LOG(ERROR) << "Failed to write string table size.";
    return false;
  }

  // Write the 'used' bitset.
  PdbBitSet bitset;
  bitset.Resize(kStringCount);
  for (size_t i = 0; i < kStringCount; ++i) {
    bitset.Set(i);
  }
  if (!bitset.Write(pdb_stream)) {
    LOG(ERROR) << "Failed to write 'used' bitset.";
    return false;
  }

  // The first bitset is always empty.
  bitset.Resize(0);
  if (!bitset.Write(pdb_stream)) {
    LOG(ERROR) << "Failed to write 'deleted' bitset.";
    return false;
  }

  // Now output the actual mapping, a run of [offset, id] pairs.
  name_it = name_stream_map.begin();
  for (size_t i = 0; name_it != name_stream_map.end(); ++i, ++name_it) {
    if (!pdb_stream->Write(offsets[i]) || !pdb_stream->Write(name_it->second)) {
      LOG(ERROR) << "Failed to write stream name mapping.";
      return false;
    }
  }

  return true;
}

}  // namespace pdb
