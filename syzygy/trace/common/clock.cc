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

#include <type_traits>

#include "base/logging.h"
#include "base/win/registry.h"

namespace trace {
namespace common {

namespace {

// We rely on TimerInfo and ClockInfo being POD types.
COMPILE_ASSERT(std::is_pod<TimerInfo>::value, TimeInfo_must_be_pod);
COMPILE_ASSERT(std::is_pod<ClockInfo>::value, ClockInfo_must_be_pod);

void GetTickTimerInfo(TimerInfo* timer_info) {
  DCHECK(timer_info != NULL);

  // Ticks are in milliseconds.
  timer_info->frequency = 1000;

  // The resolution of the tick counter varies, but is documented to have a
  // worst case of 16 ms.
  timer_info->resolution = 16;
}

union LargeInteger {
  LARGE_INTEGER li;
  uint64 ui64;
  COMPILE_ASSERT(sizeof(LARGE_INTEGER) == sizeof(uint64),
                 LARGE_INTEGER_and_uint64_must_have_same_size);
};

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

}  // namespace

bool TimerToFileTime(const FILETIME& file_time_ref,
                     const TimerInfo& timer_info,
                     const uint64& timer_ref,
                     const uint64& timer_value,
                     FILETIME* file_time) {
  DCHECK(file_time != NULL);

  // This only works if we have valid timer information.
  if (timer_info.frequency == 0 || timer_info.resolution == 0)
    return false;

  uint64 t = (static_cast<uint64>(file_time_ref.dwHighDateTime) << 32) |
      file_time_ref.dwLowDateTime;

    // The filetime is expressed in 100ns intervals.
  double cycles_per_100ns = 1.0e-7 * timer_info.frequency;
  double elapsed_100ns_intervals =
      (static_cast<double>(timer_value) - timer_ref) / cycles_per_100ns;
  double new_file_time = t + elapsed_100ns_intervals;
  if (new_file_time < 0)
    return false;

  t = static_cast<uint64>(new_file_time);
  file_time->dwLowDateTime = t & 0xFFFFFFFF;
  file_time->dwHighDateTime = t >> 32;

  return true;
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
                     uint64 ticks,
                     FILETIME* file_time) {
  DCHECK(file_time != NULL);
  return TimerToFileTime(clock_info.file_time,
                         clock_info.ticks_info,
                         clock_info.ticks_reference,
                         ticks,
                         file_time);
}

bool TscToFileTime(const ClockInfo& clock_info,
                   uint64 tsc,
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
