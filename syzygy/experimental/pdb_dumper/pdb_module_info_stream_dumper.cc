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

#include "syzygy/experimental/pdb_dumper/pdb_module_info_stream_dumper.h"

#include "syzygy/common/align.h"
#include "syzygy/experimental/pdb_dumper/pdb_dump_util.h"
#include "syzygy/experimental/pdb_dumper/pdb_symbol_record_dumper.h"
#include "syzygy/pdb/pdb_dbi_stream.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_symbol_record.h"
#include "syzygy/pe/cvinfo_ext.h"

namespace pdb {

namespace cci = Microsoft_Cci_Pdb;

namespace {

// Read the file checksum substream from a module info stream. The filenames
// used by this module will be stored in a map.
// @param file_names The map containing the filenames listed in the name stream
//     of the PDB.
// @param stream The stream containing the checksum substream.
// @param length The length of the checksum substream.
// @param module_files The map where the filenames should be saved.
// @returns true on success, false on error.
bool ReadFileChecksums(const OffsetStringMap& file_names,
                       pdb::PdbStream* stream,
                       size_t length,
                       OffsetStringMap* module_files) {
  DCHECK(stream != NULL);
  DCHECK(module_files != NULL);
  size_t base = stream->pos();
  size_t end = base + length;
  while (stream->pos() < end) {
    cci::CV_FileCheckSum checksum = {};

    size_t pos = stream->pos() - base;
    if (!stream->Read(&checksum, 1)) {
      LOG(ERROR) << "Unable to read file checksum.";
      return false;
    }
    OffsetStringMap::const_iterator it(file_names.find(checksum.name));
    if (it == file_names.end()) {
      LOG(ERROR) << "There is a checksum reference for a file that is not in "
                 << "the list of files used by this module.";
      return false;
    }
    module_files->insert(std::make_pair(pos, it->second));

    // Skip the checksum and align.
    if (!stream->Seek(common::AlignUp(stream->pos() + checksum.len, 4))) {
      LOG(ERROR) << "Unable to seek past file checksum.";
      return false;
    }
  }
  return true;
}

// Dump the line information from a line information substream.
// @param file_names The map containing the filenames used by this module.
// @param out The output where the data should be dumped.
// @param stream The stream containing the line information.
// @param length The length of the line information substream.
// @param indent_level The indentation level to use.
// @returns true on success, false on error.
bool DumpLineInfo(const OffsetStringMap& file_names,
                  FILE* out,
                  PdbStream* stream,
                  size_t length,
                  uint8 indent_level) {
  DCHECK(stream != NULL);
  size_t base = stream->pos();
  // Read the header.
  cci::CV_LineSection line_section = {};
  if (!stream->Read(&line_section, 1)) {
    LOG(ERROR) << "Unable to read line section.";
    return false;
  }

  size_t end = base + length;
  while (stream->pos() < end) {
    cci::CV_SourceFile source_file = {};
    if (!stream->Read(&source_file, 1)) {
      LOG(ERROR) << "Unable to read source info.";
      return false;
    }

    std::vector<cci::CV_Line> lines(source_file.count);
    if (lines.size() && !stream->Read(&lines, lines.size())) {
      LOG(ERROR) << "Unable to read line records.";
      return false;
    }

    std::vector<cci::CV_Column> columns(source_file.count);
    if ((line_section.flags & cci::CV_LINES_HAVE_COLUMNS) != 0 &&
        !stream->Read(&columns, columns.size())) {
      LOG(ERROR) << "Unable to read column records.";
      return false;
    }

    OffsetStringMap::const_iterator it(file_names.find(source_file.index));
    if (it == file_names.end()) {
      LOG(ERROR) << "Unable to find an index in the list of filenames used by "
                 << "this module.";
      return false;
    }
    DumpIndentedText(out,
                     indent_level,
                     "Section %d, offset 0x%04X.\n",
                     line_section.sec,
                     line_section.off);
    for (size_t i = 0; i < lines.size(); ++i) {
      if (columns[i].offColumnStart != 0) {
        DumpIndentedText(out, indent_level,
                         "%s(%d, %d): line and column at %d:%04X.\n",
                         it->second.c_str(),
                         lines[i].flags & cci::linenumStart,
                         columns[i].offColumnStart,
                         line_section.sec,
                         line_section.off + lines[i].offset);
      } else {
        DumpIndentedText(out,
                         indent_level,
                         "%s(%d): line at %d:%04X.\n",
                         it->second.c_str(),
                         lines[i].flags & cci::linenumStart,
                         line_section.sec,
                         line_section.off + lines[i].offset);
      }
    }
  }
  return true;
}

// Dump the line information substream from a module info stream.
// @param name_map The map containing the filenames listed in the name stream of
//     the PDB.
// @param out The output where the data should be dumped.
// @param stream The stream containing the line information.
// @param start The position where the line information start in the stream.
// @param lines_bytes The length of the line information substream.
// @param indent_level The level of indentation to use.
void DumpLines(const OffsetStringMap& name_map,
               FILE* out,
               pdb::PdbStream* stream,
               size_t start,
               size_t lines_bytes,
               uint8 indent_level) {
  DCHECK(stream != NULL);
  if (lines_bytes == 0)
    return;

  if (!stream->Seek(start)) {
    LOG(ERROR) << "Unable to seek to line info.";
    return;
  }

  // The line information is arranged as a back-to-back run of {type, len}
  // prefixed chunks. The types are DEBUG_S_FILECHKSMS and DEBUG_S_LINES.
  // The first of these provides file names and a file content checksum, where
  // each record is identified by its index into its chunk (excluding type
  // and len).
  size_t end = start + lines_bytes;
  OffsetStringMap file_names;
  while (stream->pos() < end) {
    uint32 line_info_type = 0;
    uint32 length = 0;
    if (!stream->Read(&line_info_type, 1) || !stream->Read(&length, 1)) {
      LOG(ERROR) << "Unable to read line info signature.";
      return;
    }

    switch (line_info_type) {
      case cci::DEBUG_S_FILECHKSMS:
        if (!ReadFileChecksums(name_map, stream, length, &file_names))
          return;
        break;
      case cci::DEBUG_S_LINES:
        if (!DumpLineInfo(file_names, out, stream, length, indent_level))
          return;
        break;
      default:
        LOG(ERROR) << "Unsupported line information type " << line_info_type
                   << ".";
        return;
    }
  }
}

}  // namespace

void DumpModuleInfoStream(const DbiModuleInfo& module_info,
                          const OffsetStringMap& name_table,
                          FILE* out,
                          PdbStream* stream) {
  DCHECK(stream != NULL);
  uint8 indent_level = 1;
  DumpIndentedText(out,
                   indent_level,
                   "Module name: %s\n",
                   module_info.module_name().c_str());
  DumpIndentedText(out,
                   indent_level,
                   "Object name: %s\n",
                   module_info.object_name().c_str());
  uint32 type = 0;
  if (!stream->Read(&type, 1) || type != cci::C13) {
    LOG(ERROR) << "Unexpected symbol stream type " << type << ".";
    return;
  }
  SymbolRecordVector symbols;
  ReadSymbolRecord(stream,
                   module_info.module_info_base().symbol_bytes - sizeof(type),
                   &symbols);
  DumpIndentedText(out, indent_level + 1, "Symbol records:\n");
  DumpSymbolRecords(out, stream, symbols, indent_level + 2);
  DumpIndentedText(out, indent_level + 1, "Lines:\n");
  DumpLines(name_table,
            out,
            stream,
            module_info.module_info_base().symbol_bytes,
            module_info.module_info_base().lines_bytes,
            indent_level + 2);
}

}  // namespace pdb
