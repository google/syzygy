#!python
# Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This file emits the list of reasons why a particular build needs to be clobbered
(or a list of 'landmines').
"""

import sys


def print_landmines():
  """
  ALL LANDMINES ARE EMITTED FROM HERE.
  """
  # DO NOT add landmines as part of a regular CL. Landmines are a last-effort
  # bandaid fix if a CL that got landed has a build dependency bug and all bots
  # need to be cleaned up. If you're writing a new CL that causes build
  # dependency problems, fix the dependency problems instead of adding a
  # landmine.
  print 'Initial landmine.'
  print 'Switch to VS2015.'


def main():
  print_landmines()
  return 0


if __name__ == '__main__':
  sys.exit(main())
