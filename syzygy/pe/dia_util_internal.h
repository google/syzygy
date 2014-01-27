// Copyright 2011 Google Inc. All Rights Reserved.
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
//
// Contains implementation details for the various templated functions declared
// in dia_util.h. Not meant to be included directly.

#ifndef SYZYGY_PE_DIA_UTIL_INTERNAL_H_
#define SYZYGY_PE_DIA_UTIL_INTERNAL_H_

#include "base/logging.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/common/com_utils.h"

namespace pe {

template <typename T>
SearchResult FindDiaTable(IDiaSession* dia_session, T** out_table) {
  return FindDiaTable(base::win::ScopedComPtr<T>::iid(),
                      dia_session,
                      reinterpret_cast<void**>(out_table));
}

template <typename T>
bool LoadDiaDebugStream(IDiaEnumDebugStreamData* stream, std::vector<T>* list) {
  DCHECK(stream != NULL);
  DCHECK(list != NULL);

  LONG count = 0;
  HRESULT hr = E_FAIL;
  if (FAILED(hr = stream->get_Count(&count))) {
    LOG(ERROR) << "Failed to get stream count: " << common::LogHr(hr) << ".";
    return false;
  }

  // Get the length of the debug stream, and ensure it is the expected size.
  DWORD bytes_read = 0;
  ULONG count_read = 0;
  hr = stream->Next(count, 0, &bytes_read, NULL, &count_read);
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to get debug stream length: "
               << common::LogHr(hr) << ".";
    return false;
  }
  DCHECK_EQ(count * sizeof(T), bytes_read);

  // Actually read the stream.
  list->resize(count);
  bytes_read = 0;
  count_read = 0;
  hr = stream->Next(count, count * sizeof(T), &bytes_read,
                    reinterpret_cast<BYTE*>(&list->at(0)),
                    &count_read);
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to read debug stream: " << common::LogHr(hr) << ".";
    return false;
  }
  DCHECK_EQ(count * sizeof(T), bytes_read);
  DCHECK_EQ(count, static_cast<LONG>(count_read));

  return true;
}

template <typename T>
SearchResult FindAndLoadDiaDebugStreamByName(const wchar_t* name,
                                             IDiaSession* dia_session,
                                             std::vector<T>* list) {
  DCHECK(name != NULL);
  DCHECK(dia_session != NULL);
  DCHECK(list != NULL);

  base::win::ScopedComPtr<IDiaEnumDebugStreamData> debug_stream;
  SearchResult search_result =
      FindDiaDebugStream(name, dia_session, debug_stream.Receive());
  if (search_result != kSearchSucceeded)
    return search_result;
  DCHECK(debug_stream.get() != NULL);

  return LoadDiaDebugStream(debug_stream.get(), list) ? kSearchSucceeded :
      kSearchErrored;
}

}  // namespace pe

#endif  // SYZYGY_PE_DIA_UTIL_INTERNAL_H_
