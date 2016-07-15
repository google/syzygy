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

#include <string>
#include <unordered_map>

#include "base/containers/hash_tables.h"
#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "base/win/iunknown_impl.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/symbols/dia_symbol_provider.h"

namespace refinery {

// Fwd.
class ProcessState;

class StackWalkHelper : public IDiaStackWalkHelper,
                        public base::win::IUnknownImpl {
 public:
  explicit StackWalkHelper(scoped_refptr<DiaSymbolProvider> symbol_provider);
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
  // TODO(manzagop): investigate for possible improvements in terms of
  // error codes returned by the current implementation.
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

  STDMETHOD(numberOfFunctionFragmentsForVA)(ULONGLONG vaFunc,
                                            DWORD cbFunc,
                                            _Out_ DWORD* pNumFragments);

  STDMETHOD(functionFragmentsForVA)(ULONGLONG vaFunc,
                                    DWORD cbFunc,
                                    DWORD cFragments,
                                    _Out_ ULONGLONG* pVaFragment,
                                    _Out_ DWORD* pLenFragment);
  // @}

 private:
  // Reads from a memory range using the actual modules as backing memory.
  // First determines how many bytes are available from the head of a range,
  // then optionally retrieves them.
  // @pre @p range must be a valid range.
  // @param range the requested range.
  // @param data_cnt on success, contains the number of bytes returned from the
  //   head of @p range.
  // @param data_ptr a buffer of size at least that of @p range or nullptr. On
  //   success, a valid buffer contains the returned data.
  // @returns true iff some data is available from the head of @p range.
  // TODO(manzagop): actually implement. Current implementation successfully
  // reads 0 bytes if the address range falls within a module.
  bool ReadFromModule(const AddressRange& range,
                      size_t* bytes_read,
                      void* buffer);

  // Backing memory for registers.
  std::unordered_map<CV_HREG_e, ULONGLONG> registers_;

  scoped_refptr<DiaSymbolProvider> symbol_provider_;
  ProcessState* process_state_;  // Not owned.
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_ANALYZERS_STACK_ANALYZER_IMPL_H_
