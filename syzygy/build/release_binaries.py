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
"""A utility script to prepare a binary release."""

import glob
import logging
import os
import re
import shutil
import subprocess
import urllib
import zipfile


_LOGGER = logging.getLogger(__name__)
_SRC_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '../..'))
_VERSION_FILE = os.path.join(_SRC_DIR, 'syzygy/VERSION')
_BINARIES_DIR = os.path.join(_SRC_DIR, 'syzygy/binaries')


_GIT_VERSION_RE = re.compile('git-svn-id:[^@]+@([0-9]+)', re.M)


_SYZYGY_RELEASE_URL = ('http://syzygy-archive.commondatastorage.googleapis.com/'
    'builds/official/%(revision)d/benchmark.zip')


def _Shell(*cmd, **kw):
  """Runs cmd, returns the results from Popen(cmd).communicate()."""
  _LOGGER.info('Executing %s.', cmd)
  prog = subprocess.Popen(cmd, shell=True, **kw)

  stdout, stderr = prog.communicate()
  if prog.returncode != 0:
    raise RuntimeError('Command "%s" returned %d.' % (cmd, prog.returncode))
  return (stdout, stderr)


def _GetFileVersion(file_path):
  # Get the most recent log message for the file, capture STDOUT.
  (stdout, dummy_stderr) = _Shell('git', 'log',
                                  '-1', file_path,
                                  stdout=subprocess.PIPE)
  match = _GIT_VERSION_RE.search(stdout)
  if not match:
    raise RuntimeError('Could not determine release version.')

  return int(match.group(1))


def main():
  # Enable info logging.
  logging.basicConfig(level=logging.INFO)

  # Retrieve the VERSION file's SVN revision number.
  revision = _GetFileVersion(_VERSION_FILE)

  # And build the corresponding archive URL.
  url = _SYZYGY_RELEASE_URL % { 'revision': revision }

  # Retrieve the corresponding archive to a temp file.
  _LOGGER.info('Retrieving release archive at "%s".', url)
  (temp_file, dummy_response) = urllib.urlretrieve(url)

  # Create a new feature branch off the master branch for the release
  # before we start changing any files.
  _LOGGER.info('Creating a release-binaries feature branch.')
  _Shell('git', 'checkout', '-b', 'release-binaries', 'master')

  # Clean out the binaries directory.
  shutil.rmtree(_BINARIES_DIR)
  os.makedirs(_BINARIES_DIR)

  # Extract the contents of the archive to the binaries directory.
  _LOGGER.info('Unzipping release archive.')
  archive = zipfile.ZipFile(temp_file, 'r')
  archive.extractall(_BINARIES_DIR)

  # Now extract the executables from the Benchmark_Chrome egg to the
  # 'exe' subdir of the binaries dir.
  egg_file = glob.glob(os.path.join(_BINARIES_DIR, 'Benchmark_Chrome*.egg'))[0]
  archive = zipfile.ZipFile(egg_file, 'r')
  exes = filter(lambda path: path.startswith('exe'), archive.namelist())
  print exes
  archive.extractall(_BINARIES_DIR, exes)

  # Add all the new files to the repo.
  _LOGGER.info('Committing release files.')
  # Update any changed or deleted files.
  _Shell('git', 'add', '-u', _BINARIES_DIR)
  # Add new files.
  _Shell('git', 'add', _BINARIES_DIR)

  # Now commit and upload the new binaries.
  message = 'Checking in version %d release binaries.' % revision
  _Shell('git', 'commit', '-m', message)
  _Shell('git', 'cl', 'upload', '-m', message)


if __name__ == '__main__':
  main()
