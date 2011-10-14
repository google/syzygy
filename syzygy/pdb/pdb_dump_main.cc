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

#include <objbase.h>
#include <iostream>
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/stringprintf.h"
#include "base/string_util.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"


std::ostream& operator<<(std::ostream& str, const GUID& guid) {
  wchar_t buf[128] = {};
  ::StringFromGUID2(guid, buf, arraysize(buf));
  str << buf;
  return str;
}

static void DumpHeaderInfoStream(pdb::PdbStream* stream) {
  pdb::PdbInfoHeader70 info = {};

  std::cout << "Header Info Stream size: " << stream->length() << std::endl;

  if (stream->Read(&info, 1)) {
    std::cout << "PDB Header Info:" << std::endl <<
        "\tversion: " << info.version << std::endl <<
        "\ttimetamp: " << info.timetamp << std::endl <<
        "\tpdb_age: " << info.pdb_age << std::endl <<
        "\tsignature: " << info.signature << std::endl;
  } else {
    LOG(ERROR) << "Unable to read PDB info header";
  }
}

static bool ReadDbiHeaders(pdb::PdbStream* stream,
                           pdb::DbiHeader* dbi_header,
                           pdb::DbiDbgHeader* dbg_header) {
  DCHECK(stream != NULL);
  DCHECK(dbi_header != NULL);
  DCHECK(dbg_header != NULL);

  if (!stream->Read(dbi_header, 1)) {
    LOG(ERROR) << "Unable to read Dbi Stream";
    return false;
  }

  if (!stream->Seek(pdb::GetDbiDbgHeaderOffset(*dbi_header)) ||
      !stream->Read(dbg_header, 1)) {
    LOG(ERROR) << "Unable to read Dbg Stream";
    return false;
  }

  return true;
}

static bool WriteStreamToPath(pdb::PdbStream* pdb_stream,
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

  LOG(INFO) << "Writing " << pdb_stream->length() << " bytes to \""
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

static void DumpDbiHeaders(const pdb::DbiHeader& dbi_header,
                           const pdb::DbiDbgHeader& dbg_header) {
  std::cout << "Dbi Header:" << std::endl <<
      "\tsignature: " << dbi_header.signature << std::endl <<
      "\tversion: " << dbi_header.version << std::endl <<
      "\tage: " << dbi_header.age << std::endl <<
      "\tglobal_symbol_info_stream: " <<
          dbi_header.global_symbol_info_stream << std::endl <<
      "\tpdb_dll_version: " << dbi_header.pdb_dll_version << std::endl <<
      "\tpublic_symbol_info_stream: " <<
          dbi_header.public_symbol_info_stream << std::endl <<
      "\tpdb_dll_build_major: " <<
          dbi_header.pdb_dll_build_major << std::endl <<
      "\tsymbol_record_stream: " <<
          dbi_header.symbol_record_stream << std::endl <<
      "\tpdb_dll_build_minor: " <<
          dbi_header.pdb_dll_build_minor << std::endl <<
      "\tgp_modi_size: " << dbi_header.gp_modi_size << std::endl <<
      "\tsection_contribution_size: " <<
          dbi_header.section_contribution_size << std::endl <<
      "\tsection_map_size: " << dbi_header.section_map_size << std::endl <<
      "\tfile_info_size: " << dbi_header.file_info_size << std::endl <<
      "\tts_map_size: " << dbi_header.ts_map_size << std::endl <<
      "\tmfc_index: " << dbi_header.mfc_index << std::endl <<
      "\tdbg_header_size: " << dbi_header.dbg_header_size << std::endl <<
      "\tec_info_size: " << dbi_header.ec_info_size << std::endl <<
      "\tflags: " << dbi_header.flags << std::endl <<
      "\tmachine: " << dbi_header.machine << std::endl <<
      "\treserved: " << dbi_header.reserved << std::endl;

  std::cout << "Dbg Header:" << std::endl <<
      "\tfpo: " << dbg_header.fpo << std::endl <<
      "\texception: " << dbg_header.exception << std::endl <<
      "\tfixup: " << dbg_header.fixup << std::endl <<
      "\tomap_to_src: " << dbg_header.omap_to_src << std::endl <<
      "\tomap_from_src: " << dbg_header.omap_from_src << std::endl <<
      "\tsection_header: " << dbg_header.section_header << std::endl <<
      "\ttoken_rid_map: " << dbg_header.token_rid_map << std::endl <<
      "\tx_data: " << dbg_header.x_data << std::endl <<
      "\tp_data: " << dbg_header.p_data << std::endl <<
      "\tnew_fpo: " << dbg_header.new_fpo << std::endl <<
      "\tsection_header_origin: " <<
          dbg_header.section_header_origin << std::endl;
}

static const char kUsage[] =
    "Usage: pdb_dump [options]\n"
    "  Dumps information from headers in a supplied PDB file, and optionally\n"
    "  writes the streams from the PDB file to individual files in a supplied\n"
    "  output directory\n"
    "\n"
    "  Required Options:\n"
    "    --input-pdb=<path> the input DLL to instrument\n"
    "  Optional Options:\n"
    "    --output-dir=<path> [optional] the output directory where the debug "
          " streams will be stored.\n";

static int Usage(const char* message) {
  std::cerr << message << std::endl << kUsage;

  return 1;
}

int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  CommandLine::Init(argc, argv);

  if (!logging::InitLogging(L"", logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
      logging::DONT_LOCK_LOG_FILE, logging::APPEND_TO_OLD_LOG_FILE,
      logging::ENABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS)) {
    return 1;
  }

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  DCHECK(cmd_line != NULL);

  FilePath input_pdb_path = cmd_line->GetSwitchValuePath("input-pdb");
  FilePath output_dir_path = cmd_line->GetSwitchValuePath("output-dir");

  if (input_pdb_path.empty())
    return Usage("You must provide an input file name.");

  pdb::PdbReader reader;
  std::vector<pdb::PdbStream*> streams;
  if (!reader.Read(input_pdb_path, &streams)) {
    LOG(ERROR) << "Failed to read PDB file " << input_pdb_path.value() << ".";
    return 1;
  }

  if (streams[pdb::kPdbHeaderInfoStream] != NULL) {
    DumpHeaderInfoStream(streams[pdb::kPdbHeaderInfoStream]);
  } else {
    LOG(ERROR) << "No header info stream.";
  }

  pdb::DbiHeader dbi_header = {};
  pdb::DbiDbgHeader dbg_header = {};
  if (streams[pdb::kDbiStream] != NULL &&
      ReadDbiHeaders(streams[pdb::kDbiStream], &dbi_header, &dbg_header)) {
    DumpDbiHeaders(dbi_header, dbg_header);
  } else {
    LOG(ERROR) << "No Dbi stream.";
  }

  std::map<size_t, std::wstring> stream_suffixes;
  stream_suffixes[pdb::kPdbHeaderInfoStream] = L"-pdb-header";
  stream_suffixes[pdb::kDbiStream] = L"-dbi";

  stream_suffixes[dbi_header.global_symbol_info_stream] = L"-globals";
  stream_suffixes[dbi_header.public_symbol_info_stream] = L"-public";
  stream_suffixes[dbi_header.symbol_record_stream] = L"-sym-record";

  stream_suffixes[dbg_header.fpo] = L"-fpo";
  stream_suffixes[dbg_header.exception] = L"-exception";
  stream_suffixes[dbg_header.fixup] = L"-fixup";
  stream_suffixes[dbg_header.omap_to_src] = L"-omap-to-src";
  stream_suffixes[dbg_header.omap_from_src] = L"-omap-from-src";
  stream_suffixes[dbg_header.section_header] = L"-section-header";
  stream_suffixes[dbg_header.token_rid_map] = L"-token-rid-map";
  stream_suffixes[dbg_header.x_data] = L"-x-data";
  stream_suffixes[dbg_header.p_data] = L"-p-data";
  stream_suffixes[dbg_header.new_fpo] = L"-new-fpo";
  stream_suffixes[dbg_header.section_header_origin] = L"-section-header-origin";

  if (!output_dir_path.empty()) {
    if (!file_util::CreateDirectory(output_dir_path)) {
      LOG(ERROR) << "Unable to create output directory '" <<
          output_dir_path.value() << "'.";

      return 1;
    }

    for (size_t i = 0; i < streams.size(); ++i) {
      if (streams[i] == NULL)
        continue;

      FilePath stream_path = output_dir_path.Append(
          base::StringPrintf(L"%d%ls", i, stream_suffixes[i].c_str()));

      if (!WriteStreamToPath(streams[i], stream_path)) {
        LOG(ERROR) << "Failed to write stream " << i << ".";
        return 1;
      }
    }
  }

  return 0;
}
