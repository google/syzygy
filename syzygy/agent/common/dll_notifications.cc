// Copyright 2013 Google Inc. All Rights Reserved.
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

// ntstatus.h conflicts with windows.h unless this is defined at inclusion.
#define WIN32_NO_STATUS
#include "syzygy/agent/common/dll_notifications.h"

#include <windows.h>
#include <winternl.h>  // For UNICODE_STRING.
#undef WIN32_NO_STATUS
#include <ntstatus.h>  // For STATUS_SUCCESS.

#include "base/logging.h"


// These structures and functions are documented in MSDN, see
// http://msdn.microsoft.com/en-us/library/gg547638(v=vs.85).aspx
// there are however no headers or import libraries available in the
// Platform SDK.
enum {
  // The DLL was loaded. The NotificationData parameter points to an
  // LDR_DLL_LOADED_NOTIFICATION_DATA structure.
  LDR_DLL_NOTIFICATION_REASON_LOADED = 1,
  // The DLL was unloaded. The NotificationData parameter points to an
  // LDR_DLL_UNLOADED_NOTIFICATION_DATA structure.
  LDR_DLL_NOTIFICATION_REASON_UNLOADED = 2,
};

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
  // Reserved.
  ULONG Flags;
  // The full path name of the DLL module.
  PCUNICODE_STRING FullDllName;
  // The base file name of the DLL module.
  PCUNICODE_STRING BaseDllName;
  // A pointer to the base address for the DLL in memory.
  PVOID DllBase;
  // The size of the DLL image, in bytes.
  ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
  // Reserved.
  ULONG Flags;
  // The full path name of the DLL module.
  PCUNICODE_STRING FullDllName;
  // The base file name of the DLL module.
  PCUNICODE_STRING BaseDllName;
  // A pointer to the base address for the DLL in memory.
  PVOID DllBase;
  // The size of the DLL image, in bytes.
  ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
  LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
  LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG notification_reason,
    const LDR_DLL_NOTIFICATION_DATA* notification_data,
    PVOID context);

typedef NTSTATUS (NTAPI *LdrRegisterDllNotificationFunc)(
  ULONG flags, PLDR_DLL_NOTIFICATION_FUNCTION notification_function,
  PVOID context, PVOID *cookie);
typedef NTSTATUS (NTAPI *LdrUnregisterDllNotificationFunc)(PVOID cookie);

namespace agent {
namespace common {

namespace {

HMODULE GetNtDll() {
  HMODULE ntdll = ::GetModuleHandle(L"ntdll.dll");
  CHECK_NE(static_cast<HMODULE>(NULL), ntdll);
  return ntdll;
}

bool Register(PLDR_DLL_NOTIFICATION_FUNCTION notify_fn,
              void* context,
              void** cookie) {
  LdrRegisterDllNotificationFunc reg_fn =
      reinterpret_cast<LdrRegisterDllNotificationFunc>(
          ::GetProcAddress(GetNtDll(), "LdrRegisterDllNotification"));

  if (reg_fn == NULL)
    return false;

  NTSTATUS status = reg_fn(0, notify_fn, context, cookie);
  return status == STATUS_SUCCESS;
}

bool Unregister(void* cookie) {
  LdrUnregisterDllNotificationFunc unreg_fn =
      reinterpret_cast<LdrUnregisterDllNotificationFunc>(
          ::GetProcAddress(GetNtDll(), "LdrUnregisterDllNotification"));

  if (unreg_fn == NULL)
    return false;

  NTSTATUS status = unreg_fn(cookie);
  return status == STATUS_SUCCESS;
}

base::StringPiece16 ToStringPiece(const UNICODE_STRING* str) {
  CHECK_NE(static_cast<const UNICODE_STRING*>(NULL), str);
  return base::StringPiece16(str->Buffer, str->Length / sizeof(wchar_t));
}

}  // namespace

DllNotificationWatcher::DllNotificationWatcher() : cookie_(NULL) {
}

DllNotificationWatcher::~DllNotificationWatcher() {
  Reset();
}

bool DllNotificationWatcher::Init(const CallbackType& callback) {
  CHECK_EQ(static_cast<void*>(NULL), cookie_);

  callback_ = callback;
  if (!Register(NotificationFunction, this, &cookie_)) {
    DCHECK_EQ(static_cast<void*>(NULL), cookie_);
    callback_.Reset();
    return false;
  }

  return true;
}

void DllNotificationWatcher::Reset() {
  if (cookie_ == NULL)
    return;

  CHECK(Unregister(cookie_));
  cookie_ = NULL;
  callback_.Reset();
}

void CALLBACK DllNotificationWatcher::NotificationFunction(
    ULONG reason, const LDR_DLL_NOTIFICATION_DATA* data, void* context) {
  CHECK_NE(static_cast<const LDR_DLL_NOTIFICATION_DATA*>(NULL), data);
  CHECK_NE(static_cast<void*>(NULL), context);

  DllNotificationWatcher* self =
      reinterpret_cast<DllNotificationWatcher*>(context);
  EventType event_type = kDllLoaded;
  HMODULE module = NULL;
  size_t module_size = 0;
  base::StringPiece16 dll_path;
  base::StringPiece16 dll_base_name;

  switch (reason) {
    case LDR_DLL_NOTIFICATION_REASON_LOADED:
      event_type = kDllLoaded;
      module = reinterpret_cast<HMODULE>(data->Loaded.DllBase);
      module_size = data->Loaded.SizeOfImage;
      dll_path = ToStringPiece(data->Loaded.FullDllName);
      dll_base_name = ToStringPiece(data->Loaded.BaseDllName);
      break;

    case LDR_DLL_NOTIFICATION_REASON_UNLOADED:
      event_type = kDllUnloaded;
      module = reinterpret_cast<HMODULE>(data->Unloaded.DllBase);
      module_size = data->Unloaded.SizeOfImage;
      dll_path = ToStringPiece(data->Unloaded.FullDllName);
      dll_base_name = ToStringPiece(data->Unloaded.BaseDllName);
      break;

    default:
      return;
  }

  self->callback_.Run(event_type, module, module_size, dll_path, dll_base_name);
}

}  // namespace common
}  // namespace agent
