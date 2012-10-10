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

from ez_setup import use_setuptools
use_setuptools()

# ez_setup bootstraps our environment and ensures that setuptools are present.
# So we can ignore pylint complaining that setuptools is not found.
# pylint: disable=F0401
from setuptools import setup

setup(name = 'dashboard',
      packages = ['handler', 'model'],
      tests_require = ['nose', 'nosegae'],
      test_suite = 'nose.collector')
