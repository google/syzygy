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
# src/build), the main difference is that this version doesn't call
# gyp_environment.SetEnvironment in its main function. This call has the side
# effect of calling vs_toolchain.py to download the toolchain, this bypasses our
# toolchain wrapper and downloads a version of the toolchain that is not the one
# we're using.

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
import landmines


def main():
  options = landmines.process_options()

  landmines_list = []
  for s in options.landmine_scripts:
    proc = subprocess.Popen([sys.executable, s], stdout=subprocess.PIPE)
    output, _ = proc.communicate()
    landmines_list.extend([('%s\n' % l.strip()) for l in output.splitlines()])
  landmines.clobber_if_necessary(landmines_list, options.src_dir)

  return 0


if __name__ == '__main__':
  sys.exit(main())
