#!python
# Copyright 2012 Google Inc. All Rights Reserved.
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
from setuptools import setup  # pylint: disable=F0401

setup(
    name='Graph-Pagefaults',
    author='Sigurdur Asgeirsson',
    author_email='siggi@chromium.org',
    version='0.1',
    package_dir = {'': '.'},
    py_modules=['graph'],
    install_requires = [
      'matplotlib',
      'ETW',
      'ETW-Db',
      'setuptools',
    ],
    entry_points={
      'console_scripts': ['graph= graph:main'],
    },
)
