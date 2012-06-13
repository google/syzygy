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

#ifndef SYZYGY_PDB_PDB_UTIL_H_
#define SYZYGY_PDB_PDB_UTIL_H_

#include <windows.h>  // NOLINT
#include <dbghelp.h>
#include <map>
#include <vector>

#include "base/file_path.h"
#include "syzygy/pdb/pdb_data.h"

namespace pdb {

// Forward declare.
class PdbFile;
class PdbStream;
class WritablePdbStream;

// A map of names to stream IDs, stored in the header stream.
typedef std::map<std::string, uint32> NameStreamMap;

// Used for parsing a variable sized bitset as found in PDB streams.
class PdbBitSet {
 public:
  // Reads a bit set from the given stream at its current cursor position.
  // @param stream the stream to be read.
  // @returns true on success, false otherwise.
  bool Read(PdbStream* stream);

  // Writes a bit set to the given stream at its current cursor position.
  bool Write(WritablePdbStream* stream);

  // Resizes the given bit set. Will be the next multiple of 32 in size.
  // @param bits the minimum number of bits to hold.
  void Resize(size_t bits);

  // Sets the given bit.
  void Set(size_t bit);

  // Clears the given bit.
  void Clear(size_t bit);

  // Toggles the given bit.
  void Toggle(size_t bit);

  // Determines if a given bit is set.
  // @param bit the position of the bit to inspect.
  // @returns true if the bit at position @p bit is set.
  bool IsSet(size_t bit) const;

  // @returns true if the bit set contains no data.
  bool IsEmpty() const;

  // @returns the number of bits in the bit set.
  size_t size() const { return bits_.size() * 32; }

 private:
  std::vector<uint32> bits_;
};

// Get the DbiDbgHeader offset within the Dbi info stream. For some reason,
// the EC info data comes before the Dbi debug header despite that the Dbi
// debug header size comes before the EC info size in the Dbi header struct.
// @param dbi_header the DBI header.
// @returns the offset in the DBI stream of the DbiDbgHeader, in bytes.
uint32 GetDbiDbgHeaderOffset(const DbiHeader& dbi_header);

// Ensures that the given stream in a PdbFile is writable.
// @param index the index of the stream to make writable.
// @param pdb_file the PdbFile containing the stream.
// @returns true on success, false otherwise.
bool EnsureStreamWritable(uint32 index, PdbFile* pdb_file);

// Sets the OMAP_TO stream in the in-memory representation of a PDB file,
// creating one if none exists.
// @param omap_to_list the list of OMAP_TO entries.
// @param pdb_file the PdbFile to be modified.
// @returns true on success, false otherwise.
bool SetOmapToStream(const std::vector<OMAP>& omap_to_list,
                     PdbFile* pdb_file);

// Sets the OMAP_FROM stream in the in-memory representation of a PDB file,
// creating one if none exists.
// @param omap_from_list the list of OMAP_FROM entries.
// @param pdb_file the PdbFile to be modified.
// @returns true on success, false otherwise.
bool SetOmapFromStream(const std::vector<OMAP>& omap_from_list,
                       PdbFile* pdb_file);

// Sets the GUID in a PDB file, resetting its age and timestamp as well.
// @param guid the new GUID for the PDB.
// @param pdb_file the PdbFile to be modified.
// @returns true on success, false otherwise.
bool SetGuid(const GUID& guid, PdbFile* pdb_file);

// Reads the header from the given PDB file @p pdb_path.
// @param pdb_path the path to the PDB whose header is to be read.
// @param pdb_header the header to be filled in.
// @returns true on success, false otherwise.
bool ReadPdbHeader(const FilePath& pdb_path, PdbInfoHeader70* pdb_header);

// Reads the header info from the given PDB stream.
// @param pdb_stream the stream containing the header.
// @param pdb_header the header to be filled in.
// @param name_stream_map the name-stream map to be filled in.
// @returns true on success, false on error.
bool ReadHeaderInfoStream(PdbStream* pdb_stream,
                          PdbInfoHeader70* pdb_header,
                          NameStreamMap* name_stream_map);

// Writes the header info to the given PDB stream.
// @param pdb_header the header to write.
// @param name_stream_map the name-stream map to write.
// @param pdb_stream the stream to be written to.
// @returns true on success, false on error.
bool WriteHeaderInfoStream(const PdbInfoHeader70& pdb_header,
                           const NameStreamMap& name_stream_map,
                           WritablePdbStream* pdb_stream);

// Reads a string from the given PDB stream.
// @param pdb_stream the stream containing the string.
// @param out the string to be read.
// @returns true on success, false on error.
bool ReadString(PdbStream* stream, std::string* out);

// Reads a string from the given PDB stream at a given position.
// @param pdb_stream the stream containing the string.
// @param pos the position where to read the string.
// @param out the string to be read.
// @returns true on success, false on error.
bool ReadStringAt(PdbStream* stream, size_t pos, std::string* out);

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_UTIL_H_
