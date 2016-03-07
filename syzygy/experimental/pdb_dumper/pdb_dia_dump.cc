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

#include <dia2.h>

#include "base/bind.h"
#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/experimental/pdb_dumper/pdb_dump_util.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/pe/find.h"

namespace pdb {

namespace {

// Return the string value associated with a SymTagEnum.
const char* GetSymTagName(enum SymTagEnum sym_tag) {
  switch (sym_tag) {
#define SYMTAG_NAME(symtag) \
    case symtag: { \
      return #symtag; \
    }
    SYMTAG_CASE_TABLE(SYMTAG_NAME)
#undef SYMTAG_NAME
    default:
      LOG(ERROR) << "Unknown SymTagEnum: " << sym_tag;
      return "<unknown>";
  }
}

void DumpProperty(FILE* out,
                  uint8_t indent_level,
                  const char* name,
                  DWORD value,
                  HRESULT hr) {
  if (hr == S_OK) {
    DumpIndentedText(out, indent_level, "%s (0x%04x)\n", name, value);
  } else if (hr == S_FALSE) {
    DumpIndentedText(out, indent_level, "%s (not supported)\n", name);
  } else {
    LOG(ERROR) << "Unable to retrieve " << name << ": " << common::LogHr(hr);
  }
}

const char kUsage[] =
    "Usage: pdb_dia_dump [options] <PDB file>...\n"
    "  Options:\n"
    "    --dump-symbols if provided, symbols will be dumped\n"
    "    --dump-frame-data if provided, frame data will be dumped\n";

}  // namespace

PdbDiaDumpApp::PdbDiaDumpApp()
    : application::AppImplBase("PDB Dia Dumper"),
      dump_symbol_data_(false),
      dump_frame_data_(false) {
}

bool PdbDiaDumpApp::ParseCommandLine(const base::CommandLine* command_line) {
  DCHECK(command_line != NULL);

  base::CommandLine::StringVector args = command_line->GetArgs();
  if (args.size() != 1U)
    return Usage("You must provide one input file.");
  pdb_path_ = base::FilePath(args[0]);

  dump_symbol_data_ = command_line->HasSwitch("dump-symbols");
  dump_frame_data_ = command_line->HasSwitch("dump-frame-data");
  if (!dump_symbol_data_ && !dump_frame_data_)
    return Usage("You must select one type of data to dump.");

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

  bool success = true;

  if (dump_symbol_data_) {
    if (!DumpSymbols(session.get())) {
      LOG(ERROR) << "Failed to dump symbols.";
      success = false;
    }
  }

  if (dump_frame_data_) {
    if (!DumpAllFrameData(session.get())) {
      LOG(ERROR) << "Failed to dump frame data.";
      success = false;
    }
  }

  return success ? 0 : 1;
}

bool PdbDiaDumpApp::Usage(const char* message) {
  ::fprintf(err(), "%s\n%s", message, kUsage);
  return false;
}

bool PdbDiaDumpApp::DumpSymbols(IDiaSession* session) {
  DCHECK(session);

  // Get the global scope.
  base::win::ScopedComPtr<IDiaSymbol> scope;
  HRESULT hr = session->get_globalScope(scope.Receive());
  if (!SUCCEEDED(hr) || !scope)
    return false;

  // Search for symbols of interest: all symbols.
  // TODO(manzagop): Look into refactoring as a pe::ChildVisitor.
  base::win::ScopedComPtr<IDiaEnumSymbols> matching_types;
  hr = scope->findChildren(SymTagNull, nullptr, nsNone,
                           matching_types.Receive());
  if (!SUCCEEDED(hr))
    return false;

  // Dump!
  LONG count = 0;
  hr = matching_types->get_Count(&count);
  if (!SUCCEEDED(hr))
    return false;

  for (LONG i = 0; i < count; ++i) {
    base::win::ScopedComPtr<IDiaSymbol> symbol;
    ULONG received = 0;
    hr = matching_types->Next(1, symbol.Receive(), &received);
    if (!SUCCEEDED(hr) || received != 1) {
      LOG(ERROR) << "Failed to get next type";
      return false;
    }
    DumpSymbol(0, symbol.get());
  }

  return true;
}

bool PdbDiaDumpApp::DumpSymbol(uint8_t indent_level, IDiaSymbol* symbol) {
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
  CHECK(pe::GetSymTag(symbol, &sym_tag));

  DumpIndentedText(out(), indent_level, "Id: %d, Name: %s (%s)\n", index_id,
                   name.c_str(), GetSymTagName(sym_tag));

  // Symbol cycle detection.
  if (visited_symbols_.find(index_id) != visited_symbols_.end()) {
    DumpIndentedText(out(), indent_level, "*Cycle*\n");
    return true;
  }
  auto insertion = visited_symbols_.insert(index_id);
  CHECK(insertion.second);

  // Output the undecorated name.
  base::string16 undecorated_name;
  if (!pe::GetSymUndecoratedName(symbol, &undecorated_name))
    undecorated_name = L"<none>";
  DumpIndentedText(out(), indent_level + 1, "undecorated_name: %ls\n",
                   undecorated_name.c_str());

  // Symtag specific output.
  // TODO(manzagop): flesh this out.
  if (sym_tag == SymTagFunction) {
    base::win::ScopedComPtr<IDiaSymbol> sym_type;
    CHECK(pe::GetSymType(symbol, &sym_type));
    DumpSymbol(indent_level + 1, sym_type.get());
  } else if (sym_tag == SymTagPublicSymbol) {
    if (undecorated_name.find(L"::`vftable'") != base::string16::npos) {
      // This is a vtable.
      LocationType location_type = LocIsNull;
      if (!pe::GetLocationType(symbol, &location_type))
        return false;

      DWORD rva;
      HRESULT hr = symbol->get_relativeVirtualAddress(&rva);
      if (hr != S_OK)
        return false;
      DumpIndentedText(out(), indent_level + 1, "rva: %x\n", rva);
    }
  }

  if (sym_tag == SymTagUDT || sym_tag == SymTagBaseClass) {
    // Dump some vtable shape information.
    base::win::ScopedComPtr<IDiaSymbol> vtable_shape;
    HRESULT hr = symbol->get_virtualTableShape(vtable_shape.Receive());
    CHECK(SUCCEEDED(hr));  // Expected to always succeed.
    if (hr == S_OK) {
      DumpIndentedText(out(), indent_level + 1, "vtable shape:\n");

      uint32_t vtable_shape_id = 0U;
      CHECK(pe::GetSymIndexId(vtable_shape.get(), &vtable_shape_id));
      DumpIndentedText(out(), indent_level + 2, "id: %d\n", vtable_shape_id);

      DWORD vtable_count = 0U;
      hr = vtable_shape->get_count(&vtable_count);
      CHECK(SUCCEEDED(hr));
      if (hr == S_OK) {
        DumpIndentedText(out(), indent_level + 2, "vtable count: %d\n",
                         vtable_count);
      } else {
        CHECK(hr == S_FALSE);
        DumpIndentedText(out(), indent_level + 2, "vtable count: none\n");
      }
    } else {
      DumpIndentedText(out(), indent_level + 1, "No vtable shape.\n");
    }
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

bool PdbDiaDumpApp::DumpAllFrameData(IDiaSession* session) {
  // Get the table that is a frame data enumerator.
  base::win::ScopedComPtr<IDiaEnumFrameData> frame_enumerator;
  pe::SearchResult result = pe::FindDiaTable(IID_IDiaEnumFrameData, session,
                                             frame_enumerator.ReceiveVoid());
  if (result != pe::kSearchSucceeded) {
    LOG(ERROR) << "Failed to get the frame table.";
    return false;
  }

  bool success = true;
  ULONG received = 0U;
  base::win::ScopedComPtr<IDiaFrameData> frame_data;
  HRESULT hr = frame_enumerator->Next(1, frame_data.Receive(), &received);
  while (hr == S_OK && received == 1) {
    if (!DumpFrameData(0, frame_data.get()))
      success = false;
    frame_data.Release();
    hr = frame_enumerator->Next(1, frame_data.Receive(), &received);
  }

  if (!SUCCEEDED(hr) || (hr == S_OK && received != 1))
    return false;

  return success;
}

bool PdbDiaDumpApp::DumpFrameData(uint8_t indent_level,
                                  IDiaFrameData* frame_data) {
  bool success = true;

  ULONGLONG code_va = 0ULL;
  CHECK_EQ(S_OK, frame_data->get_virtualAddress(&code_va));
  DWORD code_len = 0U;
  CHECK_EQ(S_OK, frame_data->get_lengthBlock(&code_len));
  DumpIndentedText(out(), indent_level,
                   "IDiaFrameData - code VA(0x%08llx) len(0x%04x)\n", code_va,
                   code_len);

  DWORD frame_type = 0U;
  CHECK_EQ(S_OK, frame_data->get_type(&frame_type));
  BOOL function_start = false;
  CHECK_EQ(S_OK, frame_data->get_functionStart(&function_start));
  DumpIndentedText(out(), indent_level + 1,
                   "frame type (%u), has function start (%d)\n", frame_type,
                   function_start);

  DWORD params_bytes = 0U;
  CHECK_EQ(S_OK, frame_data->get_lengthParams(&params_bytes));
  DWORD prolog_bytes = 0U;
  CHECK_EQ(S_OK, frame_data->get_lengthProlog(&prolog_bytes));
  DWORD registers_bytes = 0U;
  CHECK_EQ(S_OK, frame_data->get_lengthSavedRegisters(&registers_bytes));
  DumpIndentedText(out(), indent_level + 1,
                   "params (0x%04x), prolog (0x%04x), registers (0x%04x)\n",
                   params_bytes, prolog_bytes, registers_bytes);

  DWORD locals_bytes = 0U;
  CHECK_EQ(S_OK, frame_data->get_lengthLocals(&locals_bytes));
  DumpIndentedText(out(), indent_level + 1, "locals (0x%04x)\n", locals_bytes);

  DWORD max_stack_bytes = 0U;
  HRESULT hr = frame_data->get_maxStack(&max_stack_bytes);
  DumpProperty(out(), indent_level + 1, "max stack", max_stack_bytes, hr);
  if (hr != S_OK && hr != S_FALSE)
    success = false;

  base::win::ScopedBstr program_bstr;
  hr = frame_data->get_program(program_bstr.Receive());
  if (hr == S_OK) {
    DumpIndentedText(out(), indent_level + 1, "program (%ls)\n",
                     common::ToString(program_bstr));
  } else if (hr == S_FALSE) {
    DumpIndentedText(out(), indent_level + 1, "program (not supported)\n");
  } else {
    LOG(ERROR) << "Unable to retrieve program: " << common::LogHr(hr);
    success = false;
  }

  // TODO(manzagop): dump SEH info and parent.

  return success;
}

}  // namespace pdb
