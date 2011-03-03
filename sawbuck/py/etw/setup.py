#!python
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
"""Setup script for etw module."""
import sys
print sys.version

from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup


setup(name = 'ETW',
      version = '0.6.5.0',
      description = 'Utility classes for Event Tracing for Windows',
      author = 'Sigurdur Asgeirsson',
      author_email = 'siggi@chromium.org',
      url = 'http://code.google.com/p/sawbuck',
      packages = ['etw', 'etw.descriptors'],
      tests_require = ["nose>=0.9.2"],
      test_suite = 'nose.collector',
      license = 'Apache 2.0')
