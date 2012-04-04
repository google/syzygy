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
  scoped_ptr<PdbByteStream> new_dbi_stream(new PdbByteStream);
  PdbByteStream* dbi_stream = new_dbi_stream.get();
  if (pdb_file.StreamCount() <= kDbiStream ||
      !dbi_stream->Init(pdb_file.GetStream(kDbiStream))) {
    LOG(ERROR) << "Failed to initialize Dbi byte stream";
    return false;
  }

  // We explicitly transfer ownership to the PDB file.
  pdb_file.ReplaceStream(kDbiStream, new_dbi_stream.release());

  // Copy the Pdb header info stream into memory and adjust the header info.
  scoped_ptr<PdbByteStream> new_pdb_info_stream(new PdbByteStream);
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
  scoped_ptr<PdbByteStream> omap_to_stream(new PdbByteStream);
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
  scoped_ptr<PdbByteStream> omap_from_stream(new PdbByteStream);
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

}  // namespace pdb
