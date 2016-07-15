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

#include "syzygy/refinery/analyzers/stack_analyzer_impl.h"

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string16.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/refinery/core/addressed_data.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

namespace {

bool GetDiaSession(ULONGLONG va,
                   ProcessState* process_state,
                   scoped_refptr<DiaSymbolProvider> symbol_provider,
                   base::win::ScopedComPtr<IDiaSession>* session) {
  DCHECK(process_state); DCHECK(session);

  // Get the module's signature.
  ModuleLayerAccessor accessor(process_state);
  pe::PEFile::Signature signature;
  if (!accessor.GetModuleSignature(va, &signature))
    return false;

  // Retrieve the session.
  base::win::ScopedComPtr<IDiaSession> session_tmp;
  if (!symbol_provider->FindOrCreateDiaSession(signature, &session_tmp))
    return false;

  // Set the load address (the same module might be loaded at multiple VAs).
  HRESULT hr = session_tmp->put_loadAddress(signature.base_address.value());
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to set session's load address: " << common::LogHr(hr);
    return false;
  }
  *session = session_tmp;
  return true;
}

}  // namespace

StackWalkHelper::StackWalkHelper(
    scoped_refptr<DiaSymbolProvider> symbol_provider)
    : symbol_provider_(symbol_provider) {
  DCHECK(symbol_provider.get() != nullptr);
}

StackWalkHelper::~StackWalkHelper() {
}

void StackWalkHelper::SetState(StackRecordPtr stack_record,
                               ProcessState* process_state) {
  // Set up the context. For the excepting thread, we use the exception's
  // context.
  // TODO(manzagop): consider walking stack from all available contexts and
  // merging the walks.
  registers_.clear();
  DCHECK(stack_record->data().has_thread_info());
  const ThreadInformation& thread_info = stack_record->data().thread_info();
  const RegisterInformation* context;
  if (thread_info.has_exception()) {
    context = &thread_info.exception().register_info();
  } else {
    context = &thread_info.register_info();
  }

  // Set registers that are handled.
  // TODO(manzagop): should the the allreg registers also be set?
  put_registerValue(CV_REG_GS, context->seg_gs());
  put_registerValue(CV_REG_FS, context->seg_fs());
  put_registerValue(CV_REG_ES, context->seg_es());
  put_registerValue(CV_REG_DS, context->seg_ds());
  put_registerValue(CV_REG_EDI, context->edi());
  put_registerValue(CV_REG_ESI, context->esi());
  put_registerValue(CV_REG_EBX, context->ebx());
  put_registerValue(CV_REG_EDX, context->edx());
  put_registerValue(CV_REG_ECX, context->ecx());
  put_registerValue(CV_REG_EAX, context->eax());
  put_registerValue(CV_REG_EBP, context->ebp());
  put_registerValue(CV_REG_EIP, context->eip());
  put_registerValue(CV_REG_CS, context->seg_cs());
  put_registerValue(CV_REG_EFLAGS, context->eflags());
  put_registerValue(CV_REG_ESP, context->esp());
  put_registerValue(CV_REG_SS, context->seg_ss());

  // Set the process state.
  process_state_ = process_state;
}

STDMETHODIMP_(ULONG) StackWalkHelper::AddRef() {
  return base::win::IUnknownImpl::AddRef();
}

STDMETHODIMP_(ULONG) StackWalkHelper::Release() {
  return base::win::IUnknownImpl::Release();
}

STDMETHODIMP StackWalkHelper::QueryInterface(REFIID riid, PVOID* ptr_void) {
  DCHECK(ptr_void);

  if (riid == __uuidof(IDiaStackWalkHelper)) {
    *ptr_void = static_cast<IDiaStackWalkHelper*>(this);
    AddRef();
    return S_OK;
  } else {
    // Know it if another interface is requested.
    const int kGUIDSize = 39;
    std::wstring riid_str;
    int result =
        StringFromGUID2(riid, base::WriteInto(&riid_str, kGUIDSize), kGUIDSize);
    DCHECK_GT(result, 0);
    LOG(ERROR) << base::StringPrintf(L"StackWalkHelper::QueryInterface for %ls",
                                     riid_str.c_str());
    DCHECK(false);
    return base::win::IUnknownImpl::QueryInterface(riid, ptr_void);
  }
}

STDMETHODIMP StackWalkHelper::get_registerValue(DWORD index,
                                                ULONGLONG* pRetVal) {
  if (!pRetVal) {
    return E_INVALIDARG;
  }

  // Only support retrieval of registers that were previously set.
  const auto it = registers_.find(static_cast<CV_HREG_e>(index));
  if (it != registers_.end()) {
    *pRetVal = it->second;
    return S_OK;
  }

  // Even though this isn't in the function's contract, this ensures we'll pick
  // up on unexpected register retrieval attempts.
  // TODO(manzagop): add symbolic names for the registers.
  LOG(ERROR) << base::StringPrintf("Failed to get register value (%u).", index);
  DCHECK(false);
  return E_FAIL;
}

STDMETHODIMP StackWalkHelper::put_registerValue(DWORD index, ULONGLONG NewVal) {
  registers_[static_cast<CV_HREG_e>(index)] = NewVal;
  return S_OK;
}

STDMETHODIMP StackWalkHelper::readMemory(MemoryTypeEnum unused_type,
                                         ULONGLONG va,
                                         DWORD cbData,
                                         DWORD* pcbData,
                                         BYTE* pbData) {
  DCHECK(pcbData != NULL);

  // Handle the 0 size case.
  if (cbData == 0) {
    *pcbData = 0;
    return S_OK;
  }

  // Ensure range validity.
  AddressRange range(va, cbData);
  if (!range.IsValid()) {
    LOG(ERROR) << "Invalid memory range.";
    return E_FAIL;
  }

  // Read from the backing process state.
  size_t bytes_read = 0U;
  if (process_state_->GetFrom(range, &bytes_read, pbData)) {
    // Note: this may only be a partial read.
    *pcbData = bytes_read;
    return S_OK;
  }

  // If the memory comes from a module's range, attempt to service from the
  // module.
  // TODO(manzagop): success should depend on whether the module's memory
  // matches the requested memory type.
  bytes_read = 0U;
  if (ReadFromModule(range, &bytes_read, pbData)) {
    VLOG(1) << "Servicing read from module. May not reflect actual memory.";
    *pcbData = bytes_read;
    return S_OK;
  }

  // TODO(manzagop): introduce a function for logging VA to avoid crashing on
  // unexercised code when the error case occurs.
  LOG(ERROR) << base::StringPrintf("\n Read failed (va: %08llx, size: %04x)",
                                   va, cbData);
  return E_FAIL;
}

STDMETHODIMP StackWalkHelper::searchForReturnAddress(IDiaFrameData* frame,
                                                     ULONGLONG* returnAddress) {
  return E_NOTIMPL;  // Use DIA's default search.
}

STDMETHODIMP StackWalkHelper::searchForReturnAddressStart(
    IDiaFrameData* frame,
    ULONGLONG startAddress,
    ULONGLONG* returnAddress) {
  return E_NOTIMPL;  // Use DIA's default search.
}

STDMETHODIMP StackWalkHelper::frameForVA(ULONGLONG va,
                                         IDiaFrameData** frame_data) {
  base::win::ScopedComPtr<IDiaSession> session;
  if (!GetDiaSession(va, process_state_, symbol_provider_, &session)) {
    LOG(ERROR) << "Failed to get dia session.";
    return E_FAIL;
  }

  // Get the table that is a frame data enumerator.
  base::win::ScopedComPtr<IDiaEnumFrameData> frame_enumerator;
  pe::SearchResult result =
      pe::FindDiaTable(__uuidof(IDiaEnumFrameData), session.get(),
                       frame_enumerator.ReceiveVoid());
  if (result != pe::kSearchSucceeded) {
    LOG(ERROR) << "Failed to obtain frame data from the pdb.";
    return E_FAIL;
  }

  // Get the frame data.
  HRESULT hr = frame_enumerator->frameByVA(va, frame_data);
  if (hr != S_OK) {
    if (hr == S_FALSE) {
      LOG(ERROR) << "No frame data matches specified address.";
    } else {
      LOG(ERROR) << "Failed to get frame data.";
    }
  }

  return hr;
}

STDMETHODIMP StackWalkHelper::symbolForVA(ULONGLONG va, IDiaSymbol** ppSymbol) {
  base::win::ScopedComPtr<IDiaSession> session;
  if (!GetDiaSession(va, process_state_, symbol_provider_, &session)) {
    LOG(ERROR) << "Failed to get dia session.";
    return E_FAIL;
  }

  // Search for a function.
  base::win::ScopedComPtr<IDiaSymbol> function;
  HRESULT hr = session->findSymbolByVA(va, SymTagFunction, function.Receive());
  if (hr == S_OK) {
    // Get the associated function type.
    base::win::ScopedComPtr<IDiaSymbol> function_type;
    if (function->get_type(function_type.Receive()) != S_OK) {
      LOG(ERROR) << "Failed to get function's type.";
      return E_FAIL;
    }
    DWORD symtag = 0U;
    DCHECK_EQ(S_OK, function_type->get_symTag(&symtag));
    if (symtag == SymTagBaseType) {
      // We've observed a case of a function type that was a SymTagBaseType with
      // a base type of btNoType. Fail in this case.
      LOG(ERROR) << "Function's type is not SymTagFunctionType.";
      return E_FAIL;
    }
    DCHECK(symtag == SymTagFunctionType);

    *ppSymbol = function_type.Detach();
  } else {
    // Note: not having symbols is to be expected sometimes.
    LOG(INFO) << base::StringPrintf("No symbols for VA (%08llx).", va);
  }

  return hr;
}

STDMETHODIMP StackWalkHelper::pdataForVA(ULONGLONG va,
                                         DWORD cbData,
                                         DWORD* pcbData,
                                         BYTE* pbData) {
  // TODO(manzagop): implement to handle 64 bit stack walking.
  return E_NOTIMPL;
}

STDMETHODIMP StackWalkHelper::imageForVA(ULONGLONG vaContext,
                                         ULONGLONG* pvaImageStart) {
  // Get module's base address.
  // TODO(manzagop): set up indexing to optimize this.
  ModuleRecordPtr module_record;
  if (!process_state_->FindSingleRecord(vaContext, &module_record)) {
    LOG(ERROR) << "Failed to find module for VA.";
    return E_FAIL;
  }
  *pvaImageStart = module_record->range().start();
  return S_OK;
}

STDMETHODIMP StackWalkHelper::addressForVA(ULONGLONG va,
                                           _Out_ DWORD* pISect,
                                           _Out_ DWORD* pOffset) {
  base::win::ScopedComPtr<IDiaSession> session;
  if (!GetDiaSession(va, process_state_, symbol_provider_, &session)) {
    LOG(ERROR) << "Failed to get dia session.";
    return E_FAIL;
  }

  HRESULT hr = session->addressForVA(va, pISect, pOffset);
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get address for va.";
  }

  return hr;
}

STDMETHODIMP StackWalkHelper::numberOfFunctionFragmentsForVA(
    ULONGLONG vaFunc,
    DWORD cbFunc,
    _Out_ DWORD* pNumFragments) {
  // TODO(manzagop): implement this method.
  return E_NOTIMPL;
}

STDMETHODIMP StackWalkHelper::functionFragmentsForVA(
    ULONGLONG vaFunc,
    DWORD cbFunc,
    DWORD cFragments,
    _Out_ ULONGLONG* pVaFragment,
    _Out_ DWORD* pLenFragment) {
  // TODO(manzagop): implement this method.
  return E_NOTIMPL;
}

bool StackWalkHelper::ReadFromModule(const AddressRange& range,
                                     size_t* bytes_read,
                                     void* buffer) {
  DCHECK(bytes_read);
  *bytes_read = 0U;

  // Identify the module
  ModuleRecordPtr module_record;
  if (!process_state_->FindSingleRecord(range.start(), &module_record))
    return false;

  // TODO(manzagop): actually implement the read instead of successfully
  // reading 0 bytes.

  return true;
}

}  // namespace refinery
