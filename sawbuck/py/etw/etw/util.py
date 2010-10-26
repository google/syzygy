# Copyright 2010 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""General utility functions."""


# The number of seconds between 01-01-1601 and 01-01-1970
FILETIME_EPOCH_DELTA_S = 11644473600


# Multiplier to to convert from units of 100ns to seconds.
FILETIME_TO_SECONDS_MULTIPLIER = 1.0/10000000.0


def FileTimeToTime(file_time):
  """Converts a Win32 FILETIME to python-compatible time."""
  # A file time is a 64 bit integer that represents the number of 100
  # nanosecond lapses since 01-01-1601. We convert this value to seconds
  # and then change the epoch to be relative to 01-01-1970 which makes it
  # compatible with time.time().
  time_stamp_100ns = file_time
  time_stamp_s = float(time_stamp_100ns) * FILETIME_TO_SECONDS_MULTIPLIER
  return time_stamp_s - FILETIME_EPOCH_DELTA_S
