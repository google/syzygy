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

#include "syzygy/pdb/pdb_dump.h"

#include <objbase.h>
#include <algorithm>
#include <iostream>
#include <map>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "syzygy/pdb/pdb_dbi_stream.h"
#include "syzygy/pdb/pdb_reader.h"

std::ostream& operator<<(std::ostream& str, const GUID& guid) {
  wchar_t buf[128] = {};
  ::StringFromGUID2(guid, buf, arraysize(buf));
  str << buf;
  return str;
}

namespace pdb {

namespace {

// Read the stream containing the filenames listed in the Pdb.
bool ReadNameStream(PdbStream* stream, OffsetStringMap* index_strings) {
  size_t stream_start = stream->pos();
  size_t stream_end = stream->pos() + stream->length();
  return ReadStringTable(stream,
                         "Name table",
                         stream_start,
                         stream_end,
                         index_strings);
}

bool WriteStreamToPath(PdbStream* pdb_stream,
                       const FilePath& output_file_name) {
  // Open the file for output.
  FilePath output_path(output_file_name);
  file_util::ScopedFILE output_file(
      file_util::OpenFile(output_file_name, "wb"));
  if (output_file.get() == NULL) {
    LOG(ERROR) << "Unable to open \"" << output_file_name.value()
               << "\" for output.";
    return false;
  }

  VLOG(1) << "Writing " << pdb_stream->length() << " bytes to \""
          << output_file_name.value() << "\".";

  uint8 buffer[4096];
  size_t bytes_read = 0;
  pdb_stream->Seek(0);
  while (bytes_read < pdb_stream->length()) {
    size_t bytes_to_read = pdb_stream->length() - bytes_read;
    if (bytes_to_read > sizeof(buffer))
      bytes_to_read = sizeof(buffer);
    size_t bytes_just_read = 0;
    if (!pdb_stream->ReadBytes(buffer, bytes_to_read, &bytes_just_read) ||
        bytes_just_read == 0) {
      LOG(ERROR) << "Error reading " << bytes_to_read << " bytes at "
                 << "offset " << bytes_read << ".";
      return false;
    }

    if (fwrite(buffer, 1, bytes_just_read, output_file.get()) !=
        bytes_just_read) {
      LOG(ERROR) << "Error writing " << bytes_just_read << " bytes at "
          "offset " << bytes_read << ".";
      return false;
    }

    bytes_read += bytes_just_read;
  }
  return true;
}

bool ExplodeStreams(const FilePath& input_pdb_path,
                    const DbiStream& dbi_stream,
                    const NameStreamMap& name_streams,
                    const PdbFile& pdb_file) {
  FilePath output_dir_path(input_pdb_path.value() + L"-streams");
  DCHECK(!output_dir_path.empty());

  std::map<size_t, std::wstring> stream_suffixes;
  stream_suffixes[pdb::kPdbHeaderInfoStream] = L"-pdb-header";
  stream_suffixes[pdb::kDbiStream] = L"-dbi";
  stream_suffixes[pdb::kTpiStream] = L"-tpi";

  stream_suffixes[dbi_stream.header().global_symbol_info_stream] = L"-globals";
  stream_suffixes[dbi_stream.header().public_symbol_info_stream] = L"-public";
  stream_suffixes[dbi_stream.header().symbol_record_stream] = L"-sym-record";

  stream_suffixes[dbi_stream.dbg_header().fpo] = L"-fpo";
  stream_suffixes[dbi_stream.dbg_header().exception] = L"-exception";
  stream_suffixes[dbi_stream.dbg_header().fixup] = L"-fixup";
  stream_suffixes[dbi_stream.dbg_header().omap_to_src] = L"-omap-to-src";
  stream_suffixes[dbi_stream.dbg_header().omap_from_src] = L"-omap-from-src";
  stream_suffixes[dbi_stream.dbg_header().section_header] = L"-section-header";
  stream_suffixes[dbi_stream.dbg_header().token_rid_map] = L"-token-rid-map";
  stream_suffixes[dbi_stream.dbg_header().x_data] = L"-x-data";
  stream_suffixes[dbi_stream.dbg_header().p_data] = L"-p-data";
  stream_suffixes[dbi_stream.dbg_header().new_fpo] = L"-new-fpo";
  stream_suffixes[dbi_stream.dbg_header().section_header_origin] =
    L"-section-header-origin";

  NameStreamMap::const_iterator it(name_streams.begin());
  for (; it != name_streams.end(); ++it) {
    std::wstring suffix = UTF8ToWide(it->first);
    std::replace(suffix.begin(), suffix.end(), L'/', L'-');
    stream_suffixes[it->second] = suffix;
  }

  if (!file_util::CreateDirectory(output_dir_path)) {
    LOG(ERROR) << "Unable to create output directory '"
               << output_dir_path.value() << "'.";
    return false;
  }

  for (size_t i = 0; i < pdb_file.StreamCount(); ++i) {
    pdb::PdbStream* stream = pdb_file.GetStream(i);
    if (stream == NULL)
      continue;

    FilePath stream_path = output_dir_path.Append(
        base::StringPrintf(L"%d%ls", i, stream_suffixes[i].c_str()));

    if (!WriteStreamToPath(stream, stream_path)) {
      LOG(ERROR) << "Failed to write stream " << i << ".";
      return false;
    }
  }

  return true;
}

const char kUsage[] =
    "Usage: pdb_dump [options] <PDB file>...\n"
    "  Dumps information from headers in a supplied PDB files, and optionally\n"
    "  explodes the streams in the PDB files to individual files in an\n"
    "  output directory named '<PDB file>.streams'.\n"
    "\n"
    "  Optional Options:\n"
    "    --explode-streams if provided, each PDB file's streams will be\n"
    "       exploded into a directory named '<PDB file>.streams'\n";

}  // namespace

PdbDumpApp::PdbDumpApp() : explode_streams_(false) {
}

bool PdbDumpApp::ParseCommandLine(const CommandLine* command_line) {
  DCHECK(command_line != NULL);

  explode_streams_ = command_line->HasSwitch("explode-streams");

  CommandLine::StringVector args = command_line->GetArgs();
  if (args.empty())
    return Usage("You must provide at least one input file.");

  for (size_t i = 0; i < args.size(); ++i) {
    pdb_files_.push_back(FilePath(args[i]));
  }

  return true;
}

int PdbDumpApp::Run() {
  for (size_t i = 0; i < pdb_files_.size(); ++i) {
    FilePath input_pdb_path(pdb_files_[i]);
    VLOG(1) << "File \"" << input_pdb_path.value() << "\"";

    pdb::PdbReader reader;
    pdb::PdbFile pdb_file;
    if (!reader.Read(input_pdb_path, &pdb_file)) {
      LOG(ERROR) << "Failed to read PDB file " << input_pdb_path.value() << ".";
      return 1;
    }

    pdb::PdbInfoHeader70 info = {};
    NameStreamMap name_streams;
    pdb::PdbStream* stream = pdb_file.GetStream(pdb::kPdbHeaderInfoStream);
    if (stream != NULL && ReadHeaderInfoStream(stream, &info, &name_streams)) {
      DumpInfoStream(info, name_streams);
    } else {
      LOG(ERROR) << "No header info stream.";
    }

    NameStreamMap::const_iterator it(name_streams.find("/names"));
    OffsetStringMap index_names;
    if (it != name_streams.end()) {
      if (ReadNameStream(pdb_file.GetStream(it->second), &index_names)) {
        DumpNameTable(&index_names);
      } else {
        LOG(ERROR) << "Unable to read the name table.";
        return 1;
      }
    } else {
      LOG(ERROR) << "No name table.";
      return 1;
    }

    DbiStream dbi_stream;
    stream = pdb_file.GetStream(pdb::kDbiStream);
    if (stream != NULL && dbi_stream.Read(stream)) {
      DumpDbiStream(dbi_stream);
    } else {
      LOG(ERROR) << "No Dbi stream.";
      return 1;
    }

    if (explode_streams_ && !ExplodeStreams(input_pdb_path,
                                            dbi_stream,
                                            name_streams,
                                            pdb_file)) {
      return 1;
    }
  }

  return 0;
}

bool PdbDumpApp::Usage(const char* message) {
  ::fprintf(err(), "%s\n%s", message, kUsage);
  return false;
}

void PdbDumpApp::DumpInfoStream(const PdbInfoHeader70& info,
                                const NameStreamMap& name_streams) {
  ::fprintf(out(), "PDB Header Info:\n");
  ::fprintf(out(), "\tversion: %d\n", info.version);
  ::fprintf(out(), "\ttimestamp: %d\n", info.timestamp);
  ::fprintf(out(), "\tpdb_age: %d\n", info.pdb_age);
  ::fprintf(out(), "\tsignature: %d\n", info.signature);

  if (name_streams.empty())
    return;

  ::fprintf(out(), "Named Streams:\n");
  NameStreamMap::const_iterator it(name_streams.begin());
  for (; it != name_streams.end(); ++it) {
    ::fprintf(out(), "\t%s: %d\n", it->first.c_str(), it->second);
  }
}

void PdbDumpApp::DumpNameTable(OffsetStringMap* name_table) {
  DCHECK(name_table != NULL);

  ::fprintf(out(), "PDB Name table:\n");
  OffsetStringMap::iterator iter_names = name_table->begin();
  for (; iter_names != name_table->end(); ++iter_names) {
    ::fprintf(out(), "0x%04X: %s\n", iter_names->first,
              iter_names->second.c_str());
  }
}

void PdbDumpApp::DumpDbiHeaders(const DbiStream& dbi_stream) {
  ::fprintf(out(), "Dbi Header:\n");
  ::fprintf(out(), "\tsignature: %d\n", dbi_stream.header().signature);
  ::fprintf(out(), "\tversion: %d\n", dbi_stream.header().version);
  ::fprintf(out(), "\tage: %d\n", dbi_stream.header().age);
  ::fprintf(out(), "\tglobal_symbol_info_stream: %d\n",
            dbi_stream.header().global_symbol_info_stream);
  ::fprintf(out(), "\tpdb_dll_version: %d\n",
            dbi_stream.header().pdb_dll_version);
  ::fprintf(out(), "\tpublic_symbol_info_stream: %d\n",
            dbi_stream.header().public_symbol_info_stream);
  ::fprintf(out(), "\tpdb_dll_build_major: %d\n",
            dbi_stream.header().pdb_dll_build_major);
  ::fprintf(out(), "\tsymbol_record_stream: %d\n",
            dbi_stream.header().symbol_record_stream);
  ::fprintf(out(), "\tpdb_dll_build_minor: %d\n",
            dbi_stream.header().pdb_dll_build_minor);
  ::fprintf(out(), "\tgp_modi_size: %d\n", dbi_stream.header().gp_modi_size);
  ::fprintf(out(), "\tsection_contribution_size: %d\n",
            dbi_stream.header().section_contribution_size);
  ::fprintf(out(), "\tsection_map_size: %d\n",
            dbi_stream.header().section_map_size);
  ::fprintf(out(), "\tfile_info_size: %d\n",
            dbi_stream.header().file_info_size);
  ::fprintf(out(), "\tts_map_size: %d\n", dbi_stream.header().ts_map_size);
  ::fprintf(out(), "\tmfc_index: %d\n", dbi_stream.header().mfc_index);
  ::fprintf(out(), "\tdbg_header_size: %d\n",
            dbi_stream.header().dbg_header_size);
  ::fprintf(out(), "\tec_info_size: %d\n", dbi_stream.header().ec_info_size);
  ::fprintf(out(), "\tflags: %d\n", dbi_stream.header().flags);
  ::fprintf(out(), "\tmachine: %d\n", dbi_stream.header().machine);
  ::fprintf(out(), "\treserved: %d\n", dbi_stream.header().reserved);

  ::fprintf(out(), "Dbg Header:\n");
  ::fprintf(out(), "\tfpo: %d\n", dbi_stream.dbg_header().fpo);
  ::fprintf(out(), "\texception: %d\n", dbi_stream.dbg_header().exception);
  ::fprintf(out(), "\tfixup: %d\n", dbi_stream.dbg_header().fixup);
  ::fprintf(out(), "\tomap_to_src: %d\n", dbi_stream.dbg_header().omap_to_src);
  ::fprintf(out(), "\tomap_from_src: %d\n",
            dbi_stream.dbg_header().omap_from_src);
  ::fprintf(out(), "\tsection_header: %d\n",
            dbi_stream.dbg_header().section_header);
  ::fprintf(out(), "\ttoken_rid_map: %d\n",
            dbi_stream.dbg_header().token_rid_map);
  ::fprintf(out(), "\tx_data: %d\n", dbi_stream.dbg_header().x_data);
  ::fprintf(out(), "\tp_data: %d\n", dbi_stream.dbg_header().p_data);
  ::fprintf(out(), "\tnew_fpo: %d\n", dbi_stream.dbg_header().new_fpo);
  ::fprintf(out(), "\tsection_header_origin: %d\n",
            dbi_stream.dbg_header().section_header_origin);
}

void PdbDumpApp::DumpDbiStream(const DbiStream& dbi_stream) {
  DumpDbiHeaders(dbi_stream);
}

}  // namespace pdb
