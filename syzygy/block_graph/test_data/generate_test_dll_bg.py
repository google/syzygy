#!/usr/bin/python2.6
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
"""Generates serialized block-graphs representing test_dll in the Debug and
Release build configurations. This breaks the circular dependency between
block_graph_lib and pe_lib.
"""
import logging
import os
import subprocess
import sys


_LOGGER = logging.getLogger(os.path.basename(__file__))


_HERE = os.path.abspath(os.path.dirname(__file__))
_SYZYGY_DIR = os.path.dirname(os.path.dirname(_HERE))
_BUILD_DIR = os.path.join(os.path.dirname(_SYZYGY_DIR), 'build')
_TEST_UTILS = os.path.join(_SYZYGY_DIR, 'py', 'test_utils')


sys.path.insert(0, _TEST_UTILS)
import build_project


def Error(Exception):
  """Base class used for all exceptions thrown by this script."""
  pass


def BuildTestDllAndDecompose(config):
  _LOGGER.info('Building test_dll and decompose.')

  syzygy_sln = os.path.join(_SYZYGY_DIR, 'syzygy.sln')
  test_dll_proj = 'test_dll'
  decompose_proj = 'decompose'
  build_project.BuildProjectConfig(syzygy_sln, test_dll_proj, config)
  build_project.BuildProjectConfig(syzygy_sln, decompose_proj, config)


def DecomposeTestDll(config):
  _LOGGER.info('Decomposing test_dll.')

  test_dll = os.path.join(_BUILD_DIR, config, 'test_dll.dll')
  decompose = os.path.join(_BUILD_DIR, config, 'decompose.exe')
  output = os.path.join(_HERE, 'test_dll_%s.bg' % config.lower())

  # Ensure the input files exist.
  for path in [test_dll, decompose]:
    if not os.path.isfile(path):
      raise Error('Path not found: %s' % path)

  # Run the command.
  cmd = [decompose,
         '--image=%s' % test_dll,
         '--output=%s' % output,
         '--graph-only']
  _LOGGER.info('Running command %s.', cmd)
  return_code = subprocess.call(cmd)
  if return_code != 0:
    raise Error('Command failed with return code %d.' % return_code)


def Main():
  for config in ['Debug', 'Release']:
    BuildTestDllAndDecompose(config)
    DecomposeTestDll(config)


if __name__ == '__main__':
  sys.exit(Main())
