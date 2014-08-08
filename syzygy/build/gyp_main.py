# Copyright 2014 Google Inc. All Rights Reserved.
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

"""A wrapper for the gyp_main that ensures the appropriate include directories
are brought in.
"""

import os
import sys


if __name__ == '__main__':
  # Get the path of the root 'src' directory.
  self_dir = os.path.abspath(os.path.dirname(__file__))
  src_dir = os.path.abspath(os.path.join(self_dir, '..', '..'))

  # Get the path to src/build. This contains a bunch of gyp
  # 'plugins' that get called by common.gypi and base.gyp.
  build_dir = os.path.join(src_dir, 'build')

  # Get the path to the downloaded version of gyp.
  gyp_dir = os.path.join(src_dir, 'tools', 'gyp')

  # Get the path to the gyp module directoy, and the gyp_main
  # that we'll defer to.
  gyp_pylib = os.path.join(gyp_dir, 'pylib')
  gyp_main = os.path.join(gyp_dir, 'gyp_main.py')

  # Ensure the gyp plugin and module directories are in the module path
  # before passing execution to gyp_main.
  sys.path.append(gyp_pylib)
  sys.path.append(build_dir)
  execfile(gyp_main)
