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

#include "syzygy/trace/common/clock.h"

#include <WinBase.h>
#include <type_traits>

#include "base/logging.h"
#include "base/win/registry.h"

namespace trace {
namespace common {

namespace {

union LargeInteger {
  LARGE_INTEGER li;
  uint64_t ui64;
  static_assert(sizeof(LARGE_INTEGER) == sizeof(uint64_t),
                "LARGE_INTEGER and uint64_t must have the same size.");
};

typedef ULONGLONG (*GetTickCount64Ptr)();

}  // namespace

void GetTickTimerInfo(TimerInfo* timer_info) {
  DCHECK(timer_info != NULL);

  // Ticks are in milliseconds.
  timer_info->frequency = 1000;

  // The resolution of the tick counter varies, but is documented to have a
  // worst case of 16 ms.
  timer_info->resolution = 16;
}

void GetTscTimerInfo(TimerInfo* timer_info) {
  DCHECK(timer_info != NULL);

  ::memset(timer_info, 0, sizeof(TimerInfo));

  // Check the TscInvariant flag to see if we can rely on TSC as a constant
  // rate timer that is synchronous across all cores. This is in
  // CPUID.80000007.EDX[8].
  int info[4];
  ::__cpuid(info, 0x80000007);
  if ((info[3] & (1 << 8)) == 0)
    return;

  // Get the CPU frequency. If all is well, this is the frequency of the TSC
  // timer.
  base::win::RegKey cpureg;
  DWORD mhz = 0;
  if (cpureg.Open(HKEY_LOCAL_MACHINE,
                  L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                  KEY_READ) != 0 ||
      cpureg.ReadValueDW(L"~MHz", &mhz) != 0) {
    LOG(WARNING) << "Unable to get CPU frequency from registry.";
    return;
  }

  // An invariant TSC is documented to run at the fastest clock speed of the
  // CPU.
  timer_info->frequency = mhz * 1000000;
  timer_info->resolution = 1;
}

bool TimerToFileTime(const FILETIME& file_time_ref,
                     const TimerInfo& timer_info,
                     const uint64_t& timer_ref,
                     const uint64_t& timer_value,
                     FILETIME* file_time) {
  DCHECK(file_time != NULL);

  // This only works if we have valid timer information.
  if (timer_info.frequency == 0 || timer_info.resolution == 0)
    return false;

  uint64_t t = (static_cast<uint64_t>(file_time_ref.dwHighDateTime) << 32) |
               file_time_ref.dwLowDateTime;

    // The filetime is expressed in 100ns intervals.
  double cycles_per_100ns = 1.0e-7 * timer_info.frequency;
  double elapsed_100ns_intervals =
      (static_cast<double>(timer_value) - timer_ref) / cycles_per_100ns;
  double new_file_time = t + elapsed_100ns_intervals;
  if (new_file_time < 0)
    return false;

  t = static_cast<uint64_t>(new_file_time);
  file_time->dwLowDateTime = t & 0xFFFFFFFF;
  file_time->dwHighDateTime = t >> 32;

  return true;
}

uint64_t GetTicks() {
  // We can't explicitly invoke GetTickCount64 as it doesn't exist in Windows
  // XP. This would make all of our trace code unable to be run on XP systems.
  const GetTickCount64Ptr kUninitialized =
      reinterpret_cast<GetTickCount64Ptr>(1);
  static GetTickCount64Ptr get_tick_count64 = kUninitialized;

  // This is racy but safe. Worst case scenario multiple threads do the lookup,
  // each of them writing the same value to |get_tick_count64|. Since writes are
  // atomic all will be well by the time it is dereferenced.
  if (get_tick_count64 == kUninitialized) {
    HMODULE kernel32 = ::GetModuleHandleA("kernel32.dll");
    DCHECK(kernel32 != NULL);

    get_tick_count64 = reinterpret_cast<GetTickCount64Ptr>(
        ::GetProcAddress(kernel32, "GetTickCount64"));
  }
  DCHECK(get_tick_count64 != kUninitialized);

  if (get_tick_count64 != NULL)
    return (*get_tick_count64)();

  // Fall back to using the 32-bit counter if the 64-bit one is not available.
  return ::GetTickCount();
}

void GetClockInfo(ClockInfo* clock_info) {
  DCHECK(clock_info != NULL);
  ::memset(clock_info, 0, sizeof(ClockInfo));
  GetTickTimerInfo(&clock_info->ticks_info);
  GetTscTimerInfo(&clock_info->tsc_info);

  ::GetSystemTimeAsFileTime(&clock_info->file_time);

  // The TSC timer may not always be valid/available.
  if (clock_info->tsc_info.frequency)
    clock_info->tsc_reference = GetTsc();

  // The tick counter is always valid.
  clock_info->ticks_reference = GetTicks();
}

bool TicksToFileTime(const ClockInfo& clock_info,
                     uint64_t ticks,
                     FILETIME* file_time) {
  DCHECK(file_time != NULL);
  return TimerToFileTime(clock_info.file_time,
                         clock_info.ticks_info,
                         clock_info.ticks_reference,
                         ticks,
                         file_time);
}

bool TscToFileTime(const ClockInfo& clock_info,
                   uint64_t tsc,
                   FILETIME* file_time) {
  DCHECK(file_time != NULL);
  return TimerToFileTime(clock_info.file_time,
                         clock_info.tsc_info,
                         clock_info.tsc_reference,
                         tsc,
                         file_time);
}

}  // namespace common
}  // namespace trace
