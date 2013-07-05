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
//
// Declares a utility class to get DLL load/unload notifications on supporting
// systems - Vista and up.

#ifndef SYZYGY_AGENT_COMMON_DLL_NOTIFICATIONS_H_
#define SYZYGY_AGENT_COMMON_DLL_NOTIFICATIONS_H_

#include <windows.h>

#include "base/callback.h"
#include "base/strings/string_piece.h"

// Forward decl.
union _LDR_DLL_NOTIFICATION_DATA;

namespace agent {
namespace common {

// A wrapper class that assists with getting DLL load and unload notifications.
class DllNotificationWatcher {
 public:
  enum EventType {
    kDllLoaded,
    kDllUnloaded,
  };
  typedef base::Callback<void(EventType type,
                              HMODULE module,
                              size_t module_size,
                              const base::StringPiece16& dll_path,
                              const base::StringPiece16& dll_base_name)>
      CallbackType;

  DllNotificationWatcher();
  ~DllNotificationWatcher();

  // Initialize for notifications to @p callback.
  // @returns true on success, false on failure.
  // @note this will return false on systems that don't implement this
  //     mechanism, Windows XP and earlier.
  bool Init(const CallbackType& callback);

  // Uninitialize and unregister from further callbacks.
  // @note From observation, the registration and unregistration are done under
  //     loader's lock, so there's no danger of callbacks after this function
  //     returns.
  void Reset();

 private:
  static void CALLBACK NotificationFunction(
      ULONG reason,
      const union _LDR_DLL_NOTIFICATION_DATA* data,
      void* context);

  CallbackType callback_;
  void* cookie_;
};

}  // namespace common
}  // namespace agent

#endif  // SYZYGY_AGENT_COMMON_DLL_NOTIFICATIONS_H_
