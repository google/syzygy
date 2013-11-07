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
"""A utility script to prepare a binary release."""

import cStringIO
import json
import logging
import optparse
import os
import shutil
import subprocess
import urllib
import urllib2
import zipfile


_LOGGER = logging.getLogger(os.path.basename(__file__))


_SRC_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '../..'))
_VERSION_FILE = os.path.join(_SRC_DIR, 'syzygy/VERSION')
_BINARIES_DIR = os.path.join(_SRC_DIR, 'syzygy/binaries')
_EXE_DIR = os.path.join(_BINARIES_DIR, 'exe')
_INCLUDE_DIR = os.path.join(_BINARIES_DIR, 'include')
_LIB_DIR = os.path.join(_BINARIES_DIR, 'lib')


_SYZYGY_WATERFALL_URL = 'http://build.chromium.org/p/client.syzygy'
_SYZYGY_OFFICIAL = 'Syzygy Official'


_SYZYGY_ARCHIVE_URL = ('http://syzygy-archive.commondatastorage.googleapis.com/'
    'builds/official/%(revision)d')


def _Shell(*cmd, **kw):
  """Runs cmd, returns the results from Popen(cmd).communicate()."""
  _LOGGER.info('Executing %s.', cmd)
  prog = subprocess.Popen(cmd, shell=True, **kw)

  stdout, stderr = prog.communicate()
  if prog.returncode != 0:
    raise RuntimeError('Command "%s" returned %d.' % (cmd, prog.returncode))
  return (stdout, stderr)


def _Download(url):
  """Downloads the given URL and returns the contents as a string."""
  response = urllib2.urlopen(url)
  if response.code != 200:
    raise RuntimeError('Failed to download "%s".' % url)
  return response.read()


def _QueryWaterfall(path):
  """Queries the JSON API of the Syzygy waterfall."""
  url = _SYZYGY_WATERFALL_URL + '/json' + path
  data = _Download(url)
  return json.loads(data)


def _GetLastOfficialBuildRevision():
  """Query the Syzygy waterfall to get the SVN revision associated with the
  last successful official build.
  """
  # First make sure the builder doesn't have any pending builds and is idle.
  builders = _QueryWaterfall('/builders')
  if builders[_SYZYGY_OFFICIAL]['pendingBuilds'] > 0:
    raise RuntimeError('There are pending official builds.')
  if builders[_SYZYGY_OFFICIAL]['state'] != 'idle':
    raise RuntimeError('An official build is in progress.')

  # Get the information from the last build and make sure it passed before
  # extracting the revision number.
  build = _QueryWaterfall('/builders/%s/builds/-1' %
      urllib.quote(_SYZYGY_OFFICIAL))
  if 'successful' not in build['text']:
    raise RuntimeError('Last official build failed.')
  return int(build['sourceStamp']['revision'])


def main():
  option_parser = optparse.OptionParser()
  option_parser.add_option(
      '--revision', type="int",
      help='The SVN revision associated with the release build. '
           'If omitted, the SVN revision of the last successful official '
           'build will be used.')
  options, args = option_parser.parse_args()
  if args:
    option_parser.error('Unexpected arguments: %s' % args)

  # Enable info logging.
  logging.basicConfig(level=logging.INFO)

  # Get the SVN revision associated with the archived binaries to use.
  if options.revision is not None:
    revision = options.revision
  else:
    revision = _GetLastOfficialBuildRevision()
    _LOGGER.info('Using official build at revision %d.' % revision)

  # And build the corresponding archive URL.
  archive_url = _SYZYGY_ARCHIVE_URL % { 'revision': revision }
  benchmark_url = archive_url + '/benchmark.zip'
  binaries_url = archive_url + '/binaries.zip'
  symbols_url = archive_url + '/symbols.zip'
  include_url = archive_url + '/include.zip'
  lib_url = archive_url + '/lib.zip'

  # Download the archives.
  _LOGGER.info('Retrieving benchmark archive at "%s".', benchmark_url)
  benchmark_data = _Download(benchmark_url)
  _LOGGER.info('Retrieving binaries archive at "%s".', binaries_url)
  binaries_data = _Download(binaries_url)
  _LOGGER.info('Retrieving symbols archive at "%s".', symbols_url)
  symbols_data = _Download(symbols_url)
  _LOGGER.info('Retrieving include archive at "%s".', include_url)
  include_data = _Download(include_url)
  _LOGGER.info('Retrieving library archive at "%s".', lib_url)
  lib_data = _Download(lib_url)

  # Create a new feature branch off the master branch for the release
  # before we start changing any files.
  _LOGGER.info('Creating a release-binaries feature branch.')
  _Shell('git', 'checkout', '-b', 'release-binaries', 'master')

  # Clean out the output directories.
  shutil.rmtree(_BINARIES_DIR, True)
  os.makedirs(_BINARIES_DIR)
  os.makedirs(_EXE_DIR)
  os.makedirs(_INCLUDE_DIR)
  os.makedirs(_LIB_DIR)

  # Extract the contents of the benchmark archive to the binaries directory.
  _LOGGER.info('Unzipping benchmark archive.')
  archive = zipfile.ZipFile(cStringIO.StringIO(benchmark_data))
  archive.extractall(_BINARIES_DIR)

  # Extract the binaries archive to the exe directory.
  _LOGGER.info('Unzipping binaries archive.')
  archive = zipfile.ZipFile(cStringIO.StringIO(binaries_data))
  archive.extractall(_EXE_DIR)

  # Extract the symbols for the agents to the exe directory.
  _LOGGER.info('Unzipping symbols archive.')
  archive = zipfile.ZipFile(cStringIO.StringIO(symbols_data))
  for symbol in archive.infolist():
    if symbol.filename.endswith('.dll.pdb'):
      archive.extract(symbol.filename, _EXE_DIR)

  # Extract the include archive to the include directory.
  _LOGGER.info('Unzipping include archive.')
  archive = zipfile.ZipFile(cStringIO.StringIO(include_data))
  archive.extractall(_INCLUDE_DIR)

  # Extract the lib archive to the lib directory.
  _LOGGER.info('Unzipping include archive.')
  archive = zipfile.ZipFile(cStringIO.StringIO(lib_data))
  archive.extractall(_LIB_DIR)

  # Add all the new files to the repo.
  _LOGGER.info('Committing release files.')
  # Update any changed or deleted files.
  _Shell('git', 'add', '-u', _BINARIES_DIR)
  # Add new files.
  _Shell('git', 'add', _BINARIES_DIR)

  # Now commit and upload the new binaries.
  message = 'Checking in version %d release binaries.' % revision
  _Shell('git', 'commit', '-m', message)
  _Shell('git', 'cl', 'upload', '-t', message)


if __name__ == '__main__':
  main()
