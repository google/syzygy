// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/experimental/pdb_dumper/pdb_dia_dump.h"

#include "base/bind.h"
#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/experimental/pdb_dumper/pdb_dump_util.h"
#include "syzygy/pe/dia_util.h"

namespace pdb {

namespace {

bool GetSymTagName(enum SymTagEnum sym_tag, std::string* sym_tag_name) {
  DCHECK(sym_tag_name);

  // TODO(manzagop): set up something akin to SYM_TYPE_CASE_TABLE.
  switch (sym_tag) {
    case SymTagFunction:
      *sym_tag_name = "SymTagFunction";
      return true;
    case SymTagData:
      *sym_tag_name = "SymTagData";
      return true;
    case SymTagLabel:
      *sym_tag_name = "SymTagLabel";
      return true;
    case SymTagFunctionType:
      *sym_tag_name = "SymTagFunctionType";
      return true;
    case SymTagFunctionArgType:
      *sym_tag_name = "SymTagFunctionArgType";
      return true;
    case SymTagFuncDebugStart:
      *sym_tag_name = "SymTagFuncDebugStart";
      return true;
    case SymTagFuncDebugEnd:
      *sym_tag_name = "SymTagFuncDebugEnd";
      return true;
    case SymTagCallSite:
      *sym_tag_name = "SymTagCallSite";
      return true;
    case SymTagInlineSite:
      *sym_tag_name = "SymTagInlineSite";
      return true;
    case SymTagCallee:
      *sym_tag_name = "SymTagCallee";
      return true;
    default:
      base::SStringPrintf(sym_tag_name, "%d", sym_tag);
      return true;
  }
}

bool GetSymType(IDiaSymbol* symbol, base::win::ScopedComPtr<IDiaSymbol>* type) {
  DCHECK(symbol);
  DCHECK(type);

  base::win::ScopedComPtr<IDiaSymbol> tmp;
  HRESULT hr = symbol->get_type(tmp.Receive());
  if (hr != S_OK)
    return false;

  *type = tmp;
  return true;
}

const char kUsage[] = "Usage: pdb_dia_dump [options] <PDB file>...\n";

}  // namespace

PdbDiaDumpApp::PdbDiaDumpApp() : application::AppImplBase("PDB Dia Dumper") {
}

bool PdbDiaDumpApp::ParseCommandLine(const base::CommandLine* command_line) {
  DCHECK(command_line != NULL);

  base::CommandLine::StringVector args = command_line->GetArgs();
  if (args.size() != 1U)
    return Usage("You must provide one input file.");

  pdb_path_ = base::FilePath(args[0]);

  return true;
}

int PdbDiaDumpApp::Run() {
  // Create the pdb source and session.
  base::win::ScopedComPtr<IDiaDataSource> source;
  if (!pe::CreateDiaSource(source.Receive()))
    return 1;
  base::win::ScopedComPtr<IDiaSession> session;
  if (!pe::CreateDiaSession(pdb_path_, source.get(), session.Receive()))
    return 1;

  // Get the global scope.
  base::win::ScopedComPtr<IDiaSymbol> scope;
  HRESULT hr = session->get_globalScope(scope.Receive());
  if (!SUCCEEDED(hr) || !scope)
    return 1;

  // Search for the thing of interest.
  base::win::ScopedComPtr<IDiaEnumSymbols> matching_types;
  hr = scope->findChildren(SymTagNull, nullptr, nsNone,
                           matching_types.Receive());
  if (!SUCCEEDED(hr))
    return 1;

  // Dump!
  LONG count = 0;
  hr = matching_types->get_Count(&count);
  if (!SUCCEEDED(hr))
    return 1;

  for (LONG i = 0; i < count; ++i) {
    base::win::ScopedComPtr<IDiaSymbol> symbol;
    ULONG received = 0;
    hr = matching_types->Next(1, symbol.Receive(), &received);
    if (!SUCCEEDED(hr) || received != 1) {
      LOG(ERROR) << "Failed to get next type";
      return 1;
    }
    DumpSymbol(0, symbol.get());
  }

  return 0;
}

bool PdbDiaDumpApp::Usage(const char* message) {
  ::fprintf(err(), "%s\n%s", message, kUsage);
  return false;
}

bool PdbDiaDumpApp::DumpSymbol(uint8 indent_level, IDiaSymbol* symbol) {
  // Get the symbol's id, name and sym tag.
  uint32_t index_id;
  CHECK(pe::GetSymIndexId(symbol, &index_id));

  std::string name;
  base::string16 name_wide;
  if (pe::GetSymName(symbol, &name_wide)) {
    CHECK(base::WideToUTF8(name_wide.c_str(), name_wide.length(), &name));
  } else {
    name = "<none>";
  }

  enum SymTagEnum sym_tag = SymTagNull;
  std::string sym_tag_name;
  CHECK(pe::GetSymTag(symbol, &sym_tag) &&
        GetSymTagName(sym_tag, &sym_tag_name));

  DumpIndentedText(out(), indent_level, "Id: %d, Name: %s (%s)\n", index_id,
                   name.c_str(), sym_tag_name.c_str());

  // Symbol cycle detection.
  if (visited_symbols_.find(index_id) != visited_symbols_.end()) {
    DumpIndentedText(out(), indent_level, "*Cycle*\n");
    return true;
  }
  auto insertion = visited_symbols_.insert(index_id);
  CHECK(insertion.second);

  // Symtag specific output.
  // TODO(manzagop): flesh this out.
  if (sym_tag == SymTagFunction) {
    base::win::ScopedComPtr<IDiaSymbol> sym_type;
    CHECK(GetSymType(symbol, &sym_type));
    DumpSymbol(indent_level + 1, sym_type.get());
  }

  // Output the children.
  bool success = true;
  pe::ChildVisitor child_visitor(symbol, SymTagNull);
  if (!child_visitor.VisitChildren(base::Bind(&PdbDiaDumpApp::DumpSymbol,
                                              base::Unretained(this),
                                              indent_level + 1))) {
    success = false;
  }

  CHECK_EQ(visited_symbols_.erase(index_id), 1U);
  return success;
}

}  // namespace pdb
