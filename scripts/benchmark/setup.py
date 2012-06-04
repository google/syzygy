#!python
# Copyright 2012 Google Inc.
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

import distutils.command.install_data
import os.path
import pprint
import setuptools
import sys


class InstallData(distutils.command.install_data.install_data):
  """An install_data subclass to allow setting the executable directory."""
  description = "install data files"

  user_options = distutils.command.install_data.install_data.user_options[:]
  user_options.append(('exe-dir=', 'e',
       "base directory where our exe files are to be found "
       "(default: None)"))

  def initialize_options(self):
    self.exe_dir = None
    distutils.command.install_data.install_data.initialize_options(self)

  def finalize_options(self):
    distutils.command.install_data.install_data.finalize_options(self)
    if self.exe_dir:
      for dir, files in self.data_files:
        files[:] = [os.path.join(self.exe_dir, file) for file in files]


# Source directories for the packages we bundle.
_PACKAGE_DIRS = {
  '': '.',
}


# The modules we distribute.
_MODULES = [
  'benchmark',
  'chrome_control',
  'chrome_utils',
  'event_counter',
  'ibmperf',
  'instrument',
  'optimize',
  'profile',
  'runner',
  'trace_event'
]


_EXECUTABLES = [
  'call_trace_client.dll',
  'call_trace_control.exe',
  'call_trace_service.exe',
  'instrument.exe',
  'profile_client.dll',
  'relink.exe',
  'reorder.exe',
  'run_in_snapshot.exe',
  'run_in_snapshot_x64.exe',
  'run_in_snapshot_xp.exe',
  'wsdump.exe',
]


def main():
  # Build the benchmark script and the executables it depends on to a package.
  setuptools.setup(
      name='Benchmark-Chrome',
      author='Sigurdur Asgeirsson',
      author_email='siggi@chromium.org',
      version='0.1',
      url='http://no.where/',
      package_dir=_PACKAGE_DIRS,
      py_modules=_MODULES,
      data_files=[('exe', _EXECUTABLES)],
      eager_resources = ['exe/' + exe for exe in _EXECUTABLES],
      install_requires=[
        'ETW',
        'ETW-Db',
      ],
      zip_safe=True,
      entry_points={
        'console_scripts': [
            'benchmark= benchmark:main',
            'instrument= instrument:main',
            'optimize= optimize:main',
            'profile= profile:main',
        ],
      },
      cmdclass={
        "install_data": InstallData,
      }
  )


if __name__ == '__main__':
  main()
