#!python
# Copyright 2011 Google Inc. All Rights Reserved.
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
"""Utility functions for use by scripts in this directory."""

import logging
import os
import os.path
import re
import shutil
import subprocess


_LOGGER = logging.getLogger(__name__)


def Subprocess(cmd_line):
  _LOGGER.info('Running command line %s', cmd_line)
  return subprocess.call(cmd_line)


def RmTree(directory):
  """Silently do a recursive delete on directory."""
  # shutil.rmtree can't cope with read-only files.
  Subprocess(['cmd', '/c', 'rmdir', '/s', '/q', directory])


_EXPECTED_DIRS = [ 'locales', 'servers', 'extensions' ]


def _PruneDirs(dirs):
  """Removes all unwanted directories from dirs, in place."""
  for unwanted in (d for d in dirs if d.lower() not in _EXPECTED_DIRS):
    dirs.remove(unwanted)


_EXCLUDE_PATTERNS = [
    # Exclude all PDBs except for chrome_exe.pdb and chrome.dll.pdb.
    re.compile('^(?!(chrome[_\.](exe|dll))\.).+\.pdb$', re.I),
    # Exclude all test and chrome frame programs.
    re.compile('^.*(test|validate|example|sample).*$', re.I),
    # Exclude all zip/archive files.
    re.compile('^.+\.(7z|zip)$', re.I),
    ]


def _FilesToCopy(file_list):
  """Generates the filtered list of files to copy."""
  for file_name in file_list:
    if not any(p.match(file_name) for p in _EXCLUDE_PATTERNS):
      yield file_name


def CopyChromeFiles(src_dir, tgt_dir):
  """Copy all required chrome files from src_dir to tgt_dir."""
  src_dir = os.path.abspath(src_dir)
  tgt_dir = os.path.abspath(tgt_dir)
  if os.path.isdir(tgt_dir):
    RmTree(tgt_dir)
  os.makedirs(tgt_dir)
  for root_dir, sub_dirs, file_list in os.walk(src_dir):
    _PruneDirs(sub_dirs)
    for dir_name in sub_dirs:
      sub_dir = os.path.join(tgt_dir, dir_name)
      _LOGGER.info('Creating "%s".', os.path.relpath(sub_dir, tgt_dir))
      os.mkdir(sub_dir)
    for file_name in _FilesToCopy(file_list):
      src = os.path.join(root_dir, file_name)
      rel_path = os.path.relpath(src, src_dir)
      tgt = os.path.join(tgt_dir, rel_path)
      _LOGGER.info('Copying "%s".', rel_path)
      try:
        shutil.copy2(src, tgt)
      except IOError:
        # When run as part of the build, there may be build targets still in
        # flight that we don't depend on and can't copy (because they're opened
        # exclusively by the build process).  Let's assume that all the files we
        # want will copy correctly, ignore the exeption, and hope for the best
        # on the other side.
        _LOGGER.warn('Skipped "%s".', rel_path)
