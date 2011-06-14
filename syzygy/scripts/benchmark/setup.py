#!python
# Copyright 2011 Google Inc.
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
import os.path
import setuptools
import sys


# Source directories for the packages we bundle.
_PACKAGE_DIRS = {
  '': '.',
}


# The modules we distribute.
_MODULES = [
  'benchmark',
  'chrome_control',
]

_EXECUTABLES = [
  'run_in_snapshot.exe',
  'run_in_snapshot_x64.exe',
  'run_in_snapshot_xp.exe',
]


def _GetExeDir():
  """Searches for an --exe-dir switch and returns its argument.
  Removes the switch and arguments from sys.argv if found.
  """
  for i in range(len(sys.argv)):
    if sys.argv[i].startswith('--exe-dir'):
      arg = sys.argv.pop(i)
      if '=' in arg:
        return arg.split('=')[1]

      return sys.argv.pop(i)

  return '../../Release'


def main():
  exe_dir = _GetExeDir()
  exe_files = map(lambda f: os.path.join(exe_dir, f), _EXECUTABLES)
  data_files = [('exe', exe_files)]

  # Build the benchmark script and the executables it depends on to a package.
  setuptools.setup(
      name='Benchmark-Chrome',
      author='Sigurdur Asgeirsson',
      author_email='siggi@chromium.org',
      version='0.1',
      url='http://no.where/',
      package_dir=_PACKAGE_DIRS,
      py_modules=_MODULES,
      data_files=data_files,
      install_requires = [
        'ETW',
        'ETW-Db',
      ],
      zip_safe=True,
      entry_points={
        'console_scripts': ['benchmark= benchmark:main'],
      },
  )


if __name__ == '__main__':
  main()
