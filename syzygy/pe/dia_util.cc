// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/dia_util.h"

#include <diacreate.h>

#include "base/logging.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/common/com_utils.h"

namespace pe {

using base::win::ScopedBstr;
using base::win::ScopedComPtr;

const wchar_t kDiaDllName[] = L"msdia120.dll";

const wchar_t kFixupDiaDebugStreamName[] = L"FIXUP";
const wchar_t kOmapToDiaDebugStreamName[] = L"OMAPTO";
const wchar_t kOmapFromDiaDebugStreamName[] = L"OMAPFROM";

bool CreateDiaSource(IDiaDataSource** created_source) {
  DCHECK(created_source != NULL);

  *created_source = NULL;

  ScopedComPtr<IDiaDataSource> dia_source;
  HRESULT hr1 = dia_source.CreateInstance(CLSID_DiaSource);
  if (SUCCEEDED(hr1)) {
    *created_source = dia_source.Detach();
    return true;
  }

  HRESULT hr2 = NoRegCoCreate(kDiaDllName,
                              CLSID_DiaSource,
                              IID_IDiaDataSource,
                              reinterpret_cast<void**>(&dia_source));
  if (SUCCEEDED(hr2)) {
    *created_source = dia_source.Detach();
    return true;
  }

  LOG(ERROR) << "Failed to create DiaDataSource.";
  LOG(ERROR) << "  CreateInstance failed with: " << common::LogHr(hr1);
  LOG(ERROR) << "  NoRegCoCreate failed with: " << common::LogHr(hr2);

  return false;
}

bool CreateDiaSession(const base::FilePath& file,
                      IDiaDataSource* dia_source,
                      IDiaSession** dia_session) {
  DCHECK(dia_source != NULL);
  DCHECK(dia_session != NULL);

  *dia_session = NULL;

  HRESULT hr = E_FAIL;

  if (file.Extension() == L".pdb") {
    hr = dia_source->loadDataFromPdb(file.value().c_str());
  } else {
    hr = dia_source->loadDataForExe(file.value().c_str(), NULL, NULL);
  }

  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to load DIA data for \"" << file.value() << "\": "
               << common::LogHr(hr) << ".";
    return false;
  }

  ScopedComPtr<IDiaSession> session;
  hr = dia_source->openSession(session.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to open DIA session for \"" << file.value() << "\" : "
               << common::LogHr(hr) << ".";
    return false;
  }

  *dia_session = session.Detach();

  return true;
}

SearchResult FindDiaTable(const IID& iid,
                          IDiaSession* dia_session,
                          void** out_table) {
  DCHECK(dia_session != NULL);
  DCHECK(out_table != NULL);

  *out_table = NULL;

  // Get the table enumerator.
  base::win::ScopedComPtr<IDiaEnumTables> enum_tables;
  HRESULT hr = dia_session->getEnumTables(enum_tables.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to get DIA table enumerator: "
               << common::LogHr(hr) << ".";
    return kSearchErrored;
  }

  // Iterate through the tables.
  while (true) {
    base::win::ScopedComPtr<IDiaTable> table;
    ULONG fetched = 0;
    hr = enum_tables->Next(1, table.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to get DIA table: "
                 << common::LogHr(hr) << ".";
      return kSearchErrored;
    }
    if (fetched == 0)
      break;

    hr = table.QueryInterface(iid, out_table);
    if (SUCCEEDED(hr))
      return kSearchSucceeded;
  }

  // The search completed, even though we didn't find what we were looking for.
  return kSearchFailed;
}

SearchResult FindDiaDebugStream(const wchar_t* name,
                                IDiaSession* dia_session,
                                IDiaEnumDebugStreamData** dia_debug_stream) {
  DCHECK(name != NULL);
  DCHECK(dia_session != NULL);
  DCHECK(dia_debug_stream != NULL);

  *dia_debug_stream = NULL;

  HRESULT hr = E_FAIL;
  ScopedComPtr<IDiaEnumDebugStreams> debug_streams;
  if (FAILED(hr = dia_session->getEnumDebugStreams(debug_streams.Receive()))) {
    LOG(ERROR) << "Unable to get debug streams: " << common::LogHr(hr) << ".";
    return kSearchErrored;
  }

  // Iterate through the debug streams.
  while (true) {
    ScopedComPtr<IDiaEnumDebugStreamData> debug_stream;
    ULONG count = 0;
    HRESULT hr = debug_streams->Next(1, debug_stream.Receive(), &count);
    if (FAILED(hr) || (hr != S_FALSE && count != 1)) {
      LOG(ERROR) << "Unable to load debug stream: "
                 << common::LogHr(hr) << ".";
      return kSearchErrored;
    } else if (hr == S_FALSE) {
      // No more records.
      break;
    }

    ScopedBstr stream_name;
    if (FAILED(hr = debug_stream->get_name(stream_name.Receive()))) {
      LOG(ERROR) << "Unable to get debug stream name: "
                 << common::LogHr(hr) << ".";
      return kSearchErrored;
    }

    // Found the stream?
    if (wcscmp(common::ToString(stream_name), name) == 0) {
      *dia_debug_stream = debug_stream.Detach();
      return kSearchSucceeded;
    }
  }

  return kSearchFailed;
}

bool GetSymTag(IDiaSymbol* symbol, enum SymTagEnum* sym_tag) {
  DCHECK(symbol != NULL);
  DCHECK(sym_tag != NULL);
  DWORD tmp_tag = SymTagNull;
  *sym_tag = SymTagNull;
  HRESULT hr = symbol->get_symTag(&tmp_tag);
  if (hr != S_OK) {
    LOG(ERROR) << "Error getting sym tag: " << common::LogHr(hr) << ".";
    return false;
  }
  *sym_tag = static_cast<enum SymTagEnum>(tmp_tag);
  return true;
}

bool IsSymTag(IDiaSymbol* symbol, enum SymTagEnum expected_sym_tag) {
  DCHECK(symbol != NULL);
  DCHECK(expected_sym_tag != SymTagNull);

  enum SymTagEnum sym_tag = SymTagNull;
  if (!GetSymTag(symbol, &sym_tag))
    return false;

  return sym_tag == expected_sym_tag;
}

ChildVisitor::ChildVisitor(IDiaSymbol* parent, enum SymTagEnum type)
    : parent_(parent), type_(type), child_callback_(NULL) {
  DCHECK(parent != NULL);
}

bool ChildVisitor::VisitChildren(const VisitSymbolCallback& child_callback) {
  DCHECK(child_callback_ == NULL);

  child_callback_ = &child_callback;
  bool ret = VisitChildrenImpl();
  child_callback_ = NULL;

  return ret;
}

bool ChildVisitor::VisitChildrenImpl() {
  DCHECK(child_callback_ != NULL);

  // Retrieve an enumerator for all children in this PDB.
  base::win::ScopedComPtr<IDiaEnumSymbols> children;
  HRESULT hr = parent_->findChildren(type_,
                                     NULL,
                                     nsNone,
                                     children.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to get children: " << common::LogHr(hr);
    return false;
  }

  return EnumerateChildren(children);
}

bool ChildVisitor::EnumerateChildren(IDiaEnumSymbols* children) {
  DCHECK(children!= NULL);

  while (true) {
    base::win::ScopedComPtr<IDiaSymbol> child;
    ULONG fetched = 0;
    HRESULT hr = children->Next(1, child.Receive(), &fetched);
    if (FAILED(hr)) {
      DCHECK_EQ(0U, fetched);
      DCHECK(child == NULL);
      LOG(ERROR) << "Unable to iterate children: " << common::LogHr(hr);
      return false;
    }
    if (hr == S_FALSE)
      break;

    DCHECK_EQ(1U, fetched);
    DCHECK(child != NULL);

    if (!VisitChild(child))
      return false;
  }

  return true;
}

bool ChildVisitor::VisitChild(IDiaSymbol* child) {
  DCHECK(child_callback_ != NULL);

  return child_callback_->Run(child);
}

CompilandVisitor::CompilandVisitor(IDiaSession* session) : session_(session) {
  DCHECK(session != NULL);
}

bool CompilandVisitor::VisitAllCompilands(
    const VisitCompilandCallback& compiland_callback) {
  base::win::ScopedComPtr<IDiaSymbol> global;
  HRESULT hr = session_->get_globalScope(global.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to get global scope: " << common::LogHr(hr);
    return false;
  }

  ChildVisitor visitor(global, SymTagCompiland);

  return visitor.VisitChildren(compiland_callback);
}

LineVisitor::LineVisitor(IDiaSession* session, IDiaSymbol* compiland)
    : session_(session), compiland_(compiland), line_callback_(NULL) {
  DCHECK(session != NULL);
}

bool LineVisitor::VisitLines(const VisitLineCallback& line_callback) {
  DCHECK(line_callback_ == NULL);

  line_callback_ = &line_callback;
  bool ret = VisitLinesImpl();
  line_callback_ = NULL;

  return ret;
}

bool LineVisitor::EnumerateCompilandSource(IDiaSymbol* compiland,
                                           IDiaSourceFile* source_file) {
  DCHECK(compiland != NULL);
  DCHECK(source_file != NULL);

  base::win::ScopedComPtr<IDiaEnumLineNumbers> line_numbers;
  HRESULT hr = session_->findLines(compiland,
                                   source_file,
                                   line_numbers.Receive());
  if (FAILED(hr)) {
    // This seems to happen for the occasional header file.
    return true;
  }

  while (true) {
    base::win::ScopedComPtr<IDiaLineNumber> line_number;
    ULONG fetched = 0;
    hr = line_numbers->Next(1, line_number.Receive(), &fetched);
    if (FAILED(hr)) {
      DCHECK_EQ(0U, fetched);
      DCHECK(line_number == NULL);
      LOG(ERROR) << "Unable to iterate line numbers: " << common::LogHr(hr);
      return false;
    }
    if (hr == S_FALSE)
      break;

    DCHECK_EQ(1U, fetched);
    DCHECK(line_number != NULL);

    if (!VisitSourceLine(line_number))
      return false;
  }

  return true;
}

bool LineVisitor::EnumerateCompilandSources(IDiaSymbol* compiland,
                                            IDiaEnumSourceFiles* source_files) {
  DCHECK(compiland != NULL);
  DCHECK(source_files != NULL);

  while (true) {
    base::win::ScopedComPtr<IDiaSourceFile> source_file;
    ULONG fetched = 0;
    HRESULT hr = source_files->Next(1, source_file.Receive(), &fetched);
    if (FAILED(hr)) {
      DCHECK_EQ(0U, fetched);
      DCHECK(source_file == NULL);
      LOG(ERROR) << "Unable to iterate source files: " << common::LogHr(hr);
      return false;
    }
    if (hr == S_FALSE)
      break;

    DCHECK_EQ(1U, fetched);
    DCHECK(compiland != NULL);

    if (!EnumerateCompilandSource(compiland, source_file))
      return false;
  }

  return true;
}

bool LineVisitor::VisitLinesImpl() {
  DCHECK(session_ != NULL);
  DCHECK(compiland_ != NULL);
  DCHECK(line_callback_ != NULL);

  // Enumerate all source files referenced by this compiland.
  base::win::ScopedComPtr<IDiaEnumSourceFiles> source_files;
  HRESULT hr = session_->findFile(compiland_,
                                  NULL,
                                  nsNone,
                                  source_files.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to get source files: " << common::LogHr(hr);
    return false;
  }

  return EnumerateCompilandSources(compiland_, source_files);
}

bool LineVisitor::VisitSourceLine(IDiaLineNumber* line_number) {
  DCHECK(line_callback_ != NULL);

  return line_callback_->Run(line_number);
}

}  // namespace pe
