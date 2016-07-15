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
#
# This file is a wrapper for the one found in the Chromium repository (at
# src/build), with the following additions:
# - It update the path so vs_toolchain can find the scripts that it need.
# - It override the _GetDesiredVsToolchainHashes function so we can control the
#   version of the toolchain that we're using (VS2013u5 with the Win 10 SDK
#   v10240).

import json
import os
import pipes
import shutil
import subprocess
import sys


script_dir = os.path.dirname(os.path.realpath(__file__))
syzygy_src = os.path.abspath(os.path.join(script_dir, os.pardir, os.pardir))
sys.path.insert(0, os.path.join(syzygy_src, 'tools', 'gyp', 'pylib'))
sys.path.insert(0, os.path.join(syzygy_src, 'build'))


import gyp
import vs_toolchain


# Import everything from vs_toolchain to expose it to the users of this wrapper.
from vs_toolchain import *


def _GetSyzygyDesiredVsToolchainHashes():
  """Override for the vs_toolchain._GetDesiredVsToolchainHashes function to
  force it to use a specific version of the toolchain."""
  if os.environ.get('GYP_MSVS_VERSION', '2015') == '2015':
    # Update 2.
    return ['95ddda401ec5678f15eeed01d2bee08fcbc5ee97']
  else:
    print 'Error: Only VS2015 is supported.'
    sys.exit(1)


# Override the vs_toolchain._GetDesiredVsToolchainHashes function.
vs_toolchain._GetDesiredVsToolchainHashes = _GetSyzygyDesiredVsToolchainHashes


def main():
  return vs_toolchain.main()


if __name__ == '__main__':
  sys.exit(main())
