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

#ifndef SYZYGY_REFINERY_ANALYZERS_STACK_ANALYZER_IMPL_H_
#define SYZYGY_REFINERY_ANALYZERS_STACK_ANALYZER_IMPL_H_

#include <dia2.h>

#include <hash_map>
#include <map>
#include <string>

#include "base/containers/hash_tables.h"
#include "base/files/file_path.h"
#include "base/win/iunknown_impl.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/refinery/process_state/process_state_util.h"

namespace refinery {

// Fwd.
class ProcessState;

class StackWalkHelper : public IDiaStackWalkHelper,
                        public base::win::IUnknownImpl {
 public:
  StackWalkHelper();
  ~StackWalkHelper() override;

  // Sets up the stack walk helper's state.
  // @param stack_record the record of the stack to walk.
  // @param process_state the state of the process; must outlive this class.
  void SetState(StackRecordPtr stack_record, ProcessState* process_state);

  // @name IUnknown implementation
  // @{
  ULONG STDMETHODCALLTYPE AddRef() override;
  ULONG STDMETHODCALLTYPE Release() override;
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, PVOID*) override;
  // @}

  // @name IDiaStackWalkHelper implementation
  // @{
  STDMETHOD(get_registerValue)(DWORD index, ULONGLONG* pRetVal);
  STDMETHOD(put_registerValue)(DWORD index, ULONGLONG NewVal);
  STDMETHOD(readMemory)(MemoryTypeEnum type,
                        ULONGLONG va,
                        DWORD cbData,
                        DWORD* pcbData,
                        BYTE* pbData);
  STDMETHOD(searchForReturnAddress)(IDiaFrameData* frame,
                                    ULONGLONG* returnAddress);

  STDMETHOD(searchForReturnAddressStart)(IDiaFrameData* frame,
                                         ULONGLONG startAddress,
                                         ULONGLONG* returnAddress);

  STDMETHOD(frameForVA)(ULONGLONG va, IDiaFrameData** ppFrame);

  STDMETHOD(symbolForVA)(ULONGLONG va, IDiaSymbol** ppSymbol);

  STDMETHOD(pdataForVA)(ULONGLONG va,
                        DWORD cbData,
                        DWORD* pcbData,
                        BYTE* pbData);

  STDMETHOD(imageForVA)(ULONGLONG vaContext, ULONGLONG* pvaImageStart);

  STDMETHOD(addressForVA)(ULONGLONG va,
                          _Out_ DWORD* pISect,
                          _Out_ DWORD* pOffset);
  // @}

 private:
  bool EnsurePdbSessionCached(const pe::PEFile::Signature& signature,
                              std::wstring* cache_key);
  bool GetDiaSessionByVa(ULONGLONG va, IDiaSession** session);

  // Backing memory for registers.
  base::hash_map<CV_HREG_e, ULONGLONG> registers_;

  // Caching for dia pdb file sources and sessions (matching entries). The cache
  // key is "<basename>:<size>:<checksum>:<timestamp>". The cache may contain
  // negative entries (indicating a failed attempt at creating a session) in the
  // form of null pointers.
  std::map<std::wstring, base::win::ScopedComPtr<IDiaDataSource>> pdb_sources_;
  std::map<std::wstring, base::win::ScopedComPtr<IDiaSession>> pdb_sessions_;

  ProcessState* process_state_;  // Not owned.
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_ANALYZERS_STACK_ANALYZER_IMPL_H_
