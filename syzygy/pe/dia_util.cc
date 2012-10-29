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
#include "sawbuck/common/com_utils.h"

namespace pe {

using base::win::ScopedBstr;
using base::win::ScopedComPtr;

const wchar_t kDiaDllName[] = L"msdia100.dll";
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
  LOG(ERROR) << "  CreateInstance failed with: " << com::LogHr(hr1);
  LOG(ERROR) << "  NoRegCoCreate failed with: " << com::LogHr(hr2);

  return false;
}

bool CreateDiaSession(const FilePath& file,
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
               << com::LogHr(hr) << ".";
    return false;
  }

  ScopedComPtr<IDiaSession> session;
  hr = dia_source->openSession(session.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to open DIA session for \"" << file.value() << "\" : "
               << com::LogHr(hr) << ".";
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
               << com::LogHr(hr) << ".";
    return kSearchErrored;
  }

  // Iterate through the tables.
  while (true) {
    base::win::ScopedComPtr<IDiaTable> table;
    ULONG fetched = 0;
    hr = enum_tables->Next(1, table.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to get DIA table: "
                 << com::LogHr(hr) << ".";
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
    LOG(ERROR) << "Unable to get debug streams: " << com::LogHr(hr) << ".";
    return kSearchErrored;
  }

  // Iterate through the debug streams.
  while (true) {
    ScopedComPtr<IDiaEnumDebugStreamData> debug_stream;
    ULONG count = 0;
    HRESULT hr = debug_streams->Next(1, debug_stream.Receive(), &count);
    if (FAILED(hr) || (hr != S_FALSE && count != 1)) {
      LOG(ERROR) << "Unable to load debug stream: "
                 << com::LogHr(hr) << ".";
      return kSearchErrored;
    } else if (hr == S_FALSE) {
      // No more records.
      break;
    }

    ScopedBstr stream_name;
    if (FAILED(hr = debug_stream->get_name(stream_name.Receive()))) {
      LOG(ERROR) << "Unable to get debug stream name: "
                 << com::LogHr(hr) << ".";
      return kSearchErrored;
    }

    // Found the stream?
    if (wcscmp(com::ToString(stream_name), name) == 0) {
      *dia_debug_stream = debug_stream.Detach();
      return kSearchSucceeded;
    }
  }

  return kSearchFailed;
}

}  // namespace pe
