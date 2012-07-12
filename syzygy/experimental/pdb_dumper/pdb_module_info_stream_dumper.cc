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

#include "syzygy/experimental/pdb_dumper/cvinfo_ext.h"
#include "syzygy/experimental/pdb_dumper/pdb_dump_util.h"
#include "syzygy/experimental/pdb_dumper/pdb_symbol_record_dumper.h"
#include "syzygy/pdb/pdb_dbi_stream.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_symbol_record.h"

namespace pdb {

namespace cci = Microsoft_Cci_Pdb;

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
  DumpSymbolRecord(out, stream, symbols, indent_level + 1);
  // TODO(sebmarchand): Dump line info.
}

}  // namespace pdb
