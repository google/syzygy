#!/usr/bin/python2.4
#
# Copyright 2012 Google Inc. All Rights Reserved.
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

"""Browse and retrieve builds from a chrome build repository."""

# Standard imports
import cStringIO as StringIO
import datetime
import httplib
import optparse
import os
import posixpath
import re
import shutil
import socket
import sys
import urllib2
import urlparse
import zipfile

# Local imports
import log_helper


# The default regular expresson to use when searching for build ids.
DEFAULT_BUILD_ID_PATTERN = r'\d+\.\d+\.\d+\.\d+'


# The list of files we're interested in.
FILE_LIST = [
    'chrome-win32-syms.zip',
    'chrome-win32.zip',
    'chrome-win32.test/automated_ui_tests.exe',
    'chrome-win32.test/reliability_tests.exe',
    ]


# The set of build subdirs we're interested in. There has been some flakiness
# in building the latest whole-program-optimized official binaries in 'win',
# so an unoptimized build has been introduced in 'win_unopt'. We can try them
# in priority order when looking for a successful build, giving preference
# to the optimized build.
SUBDIRS = [ 'win', 'win_unopt' ]


# The logger object used by this module
_LOGGER = log_helper.GetLogger(__file__)


class Error(Exception):
  """Base class for all exception thrown by this module."""
  pass


class DownloadError(Error):
  """Raised on errors when downloading from the repository."""
  pass


class FormatError(Error):
  """Raised on errors parsing a response from the repository."""
  pass


class NotFoundError(Error):
  """Raised on errors searching the repository for a build id."""
  pass


class ChromeRepo(object):
  """Browses and retrieves builds from a chrome build repository."""

  # Python's date parsing utilities depend on the locale ... decouple that.
  _MONTHS = {
      'jan' : 1, 'feb' : 2, 'mar' : 3, 'apr' :  4, 'may' :  5, 'jun' :  6,
      'jul' : 7, 'aug' : 8, 'sep' : 9, 'oct' : 10, 'nov' : 11, 'dec' : 12,
      }

  # Used to extract the date from an HTML directory listing.
  _BUILD_DATE_REGEX = re.compile(
      r'(?P<day>[0-3]\d)-(?P<month>(%s))-(?P<year>\d{4})\s+'
      r'(?P<hours>[0-2]\d):(?P<minutes>[0-5]\d)' % '|'.join(_MONTHS.keys()),
      re.IGNORECASE | re.VERBOSE)

  def __init__(self, repo_url,
               build_id_pattern=DEFAULT_BUILD_ID_PATTERN,
               proxy_server=None):
    """Initialize a ChromeRepo instance.

    Args:
      repo_url: The root url which returns the contents of the repository
          as a directory listing.
      build_id_pattern: The regular expression pattern to use for identifying
          build id strings. This allows you to be more specific in your
          searches. For example you can specify "10\.\d+\.\d+\.\d+" to get
          all version 10 builds.
      proxy_server: The URL to the HTTP(s) proxy server to use, or None, if no
          proxy server is to be explicitly set.
    """
    # pylint: disable=E1103
    #   --> pylint can't infer the named properties of a SplitResult.
    url_parts = urlparse.urlsplit(repo_url)
    self._scheme = url_parts.scheme.lower()
    self._netloc = url_parts.netloc
    self._root_dir = url_parts.path
    self._query = url_parts.query
    self._fragment = url_parts.fragment
    # pylint: enable=E1103

    if self._scheme not in ('http', 'https'):
      raise ValueError('Unsupported URL scheme (%s)' % self._scheme)

    if proxy_server:
      custom_handlers = [urllib2.ProxyHandler({self._scheme:proxy_server})]
    else:
      custom_handlers = []

    self._url_opener = urllib2.build_opener(*custom_handlers)
    self._build_id_pattern = build_id_pattern
    self._build_id_regex = re.compile(r'href="(?P<id>%s)/"' % build_id_pattern)

  def _PerformRequest(self, method, path, out_stream, body=None, headers=None,
                      max_attempts=3):
    """Carries out an HTTP request.

    The server used will be that given in the repo_url parameter when this
    ChromeRepo object was initialized.

    Args:
      method: The HTTP method.
      path: The path of the request (including query params, fragments, etc).
      out_stream: A file object to which the response body will be written.
      body: The optional body to include in the request.
      headers: The optional HTTP headers to include in the request.
      max_attempts: The maximum number of times to attempt the request if it
          fails due to a server or network error (default: 3).

    Returns:
      A triple containing the HTTP status code, the headers of the response,
      and the complete URL of the request.  The body of the response will have
      been written to the out_stream parameter.
    """
    chunk_size = 32768
    url = '%s://%s%s' % (self._scheme, self._netloc, path)
    error_result = -1, {}, url
    _LOGGER.debug('Performing %s to %s', method, url)
    for attempt in xrange(1, max_attempts + 1):
      try:
        request = urllib2.Request(url, body, headers or {})
        response = self._url_opener.open(request)
        while out_stream is not None:
          chunk = response.read(chunk_size)
          if not chunk:
            break
          out_stream.write(chunk)
        return 200, response.info(), response.geturl()
      except (IOError, socket.error, httplib.HTTPException), error:
        _LOGGER.error('[%d/%d] %s', attempt, max_attempts, error)
        status = (error.code if hasattr(error, 'code') else 500)
        error_result = status, {}, url
        if status >= 400 and status < 500:
          break
        out_stream.seek(0)
    return error_result

  def GetBuildIndex(self):
    """Retrieve the list of build (id, timestamp) pairs from the build repo.

    The returned list will be sorted from most recently to least recently
    modified.  Note that it's possible that a build is in progress, so you
    may not want to take the most recently modified build.
    """
    build_index = list()
    response_buffer = StringIO.StringIO()
    url_parts = (None, None, self._root_dir, self._query, self._fragment)
    path = urlparse.urlunsplit(url_parts)
    status, _headers, url = self._PerformRequest('GET', path, response_buffer)
    if status != 200:
      message = '(%s) Failed to download index [%s]' % (status, url)
      _LOGGER.error('%s', message)
      raise DownloadError(message)
    for line in response_buffer.getvalue().split('\n'):
      id_match = self._build_id_regex.search(line)
      if not id_match:
        continue
      date_match = self._BUILD_DATE_REGEX.search(line)
      if not date_match:
        raise FormatError('Found build id but no date!: %s' % line)
      build_id = id_match.group('id')
      timestamp = datetime.datetime(
          year=int(date_match.group('year')),
          month=self._MONTHS[date_match.group('month').lower()],
          day=int(date_match.group('day')),
          hour=int(date_match.group('hours')),
          minute=int(date_match.group('minutes')))
      sort_key = (timestamp,) + tuple(int(x) for x in build_id.split('.'))
      build_index.append((build_id, timestamp, sort_key))
    return sorted(build_index, key=lambda x: x[2], reverse=True)

  def _GetFilePath(self, build_id, subdir, relative_path):
    """Generates the path in the repo to a given file for a given build.

    Args:
      build_id: The identifier for the build
      subdir: The build sub-directory for the file.
      relative_path: The path to the file, relative to the windows build
          root for build_id and the subdir.

    Returns:
      The absolute path (a string) to the file in the repository.
    """
    return posixpath.join(self._root_dir, build_id, subdir, relative_path)

  def _FileExists(self, path):
    """Checks if the build artifact given by path exists in the build repo.
    Args:
      path: The path to the build artifact. Use _GetFilePath to construct
          an appropriate path.

    Returns:
      true if the artifact exists.
    """
    status, _headers, _url = self._PerformRequest('HEAD', path, None,
                                                  max_attempts=2)
    return status == 200

  def GetLatestBuildId(self, build_index=None):
    """Pulls out the id and timestamp of the lastest build.

    Searches through the (already sorted by date) build_index for the
    first build archive that contains all of the required files (i.e.,
    that's not a build in progress).

    Args:
      build_index: The index to search, if you've already downloaded it.
          If None, it will be downloaded automatically.

    Returns:
      A build-id (string), timestamp (datetime) pair; or (None, None) if
      no valid build can be found.
    """
    if build_index is None:
      build_index = self.GetBuildIndex()

    for build_id, timestamp, _sort_key in build_index:
      found = True
      for subdir in SUBDIRS:
        for file_name in FILE_LIST:
          path = self._GetFilePath(build_id, subdir, file_name)
          if not self._FileExists(path):
            _LOGGER.debug('Build %s is missing %s', build_id, file_name)
            found = False
            break
        if found:
          _LOGGER.info('Build %s has all required files', build_id)
          return build_id, timestamp, subdir

    raise NotFoundError(
        'No latest build found matching %s' % self._build_id_pattern)

  def DownloadBuild(self, work_dir, build_id=None, subdir=None):
    """Download a build (by id or latest) into work_dir/build_id.

    Args:
      work_dir: The directory in which to place the downloaded files
      build_id: the (optional) id of the build to fetch.  If not
          specified, this will download the "latest" build.
      subdir: The build sub-directory for the files.

    Returns:
      The final path to the extracted chrome directory; for
      example, work_dir/build_id. Under that directory will be the
      chrome_win32 and chrome-win32-syms directories.
    """
    if build_id is None:
      build_id, dummy_timestamp, subdir = self.GetLatestBuildId()
    elif subdir is None:
      for ddir in SUBDIRS:
        if self._FileExists(self._GetFilePath(build_id, ddir, FILE_LIST[0])):
          subdir = ddir
          break
      if subdir is None:
        raise NotFoundError(
            'Could not find build artifacts for build %s' % build_id)

    build_dir = os.path.abspath(os.path.join(work_dir, build_id))
    chrome_dir = os.path.abspath(os.path.join(build_dir, 'chrome-win32'))
    if not os.path.exists(build_dir):
      os.makedirs(build_dir)
    for file_name in FILE_LIST:
      _LOGGER.info('Downloading %s', file_name)
      name = os.path.basename(file_name)
      dest = os.path.join(build_dir, name)
      with open(dest, 'wb') as out_stream:
        status, headers, url = self._PerformRequest(
            'GET', self._GetFilePath(build_id, subdir, file_name), out_stream)
      if status == 404:
        os.remove(dest)
        raise NotFoundError('(%s) Not Found - %s' % (status, file_name))
      if status != 200 \
          or int(headers['Content-Length']) != os.stat(dest).st_size:
        os.remove(dest)
        raise DownloadError('(%s) Failed to download %s' % (status, url))
      if file_name.lower().endswith('.zip'):
        _LOGGER.info('Extracting files from %s', dest)
        zipfile.ZipFile(dest, 'r', allowZip64=True).extractall(build_dir)
        _LOGGER.info('Extraction complete.')
        os.remove(dest)
      else:
        shutil.move(dest, os.path.join(chrome_dir, name))
    return build_dir


def AddCommandLineOptions(option_parser):
  """Adds the group of repository related options to the given option_parser.

  Args:
    option_parser: the option parser object to update.  This is expected
        to be an instance of optparse.OptionParser.
  """
  group = optparse.OptionGroup(option_parser, 'Build Repository Options')
  group.add_option(
      '--repo-url', metavar='URL',
      help='The root url where builds are archived')
  group.add_option(
      '--repo-build-id', metavar='ID', help='The id of the build do download')
  group.add_option(
      '--repo-work-dir', metavar='DIR', default='.',
      help='Where to put downloaded builds')
  group.add_option(
      '--repo-build-id-pattern', metavar='PATTERN',
      default=DEFAULT_BUILD_ID_PATTERN,
      help='Regular expression for recognizing build ids (default: %default)')
  group.add_option(
      '--repo-build-subdir', metavar='DIR',
      help='The subdirectory in which the unoptimized build resides.')
  group.add_option(
      '--repo-proxy', metavar='URL',
      help='The proxy server to use when accessing the repository')
  option_parser.add_option_group(group)
  return group


def ParseArgs():
  """Parse the command line options, returning an options object."""
  usage = 'Usage: %prog [options] LIST|GET|LATEST'
  option_parser = optparse.OptionParser(usage)
  AddCommandLineOptions(option_parser)
  log_helper.AddCommandLineOptions(option_parser)
  options, args = option_parser.parse_args()
  if not options.repo_url:
    option_parser.error('--repo-url is required')
  if len(args) == 1:
    action = args[0].lower()
    if action in ('list', 'latest', 'get'):
      return options, action
  option_parser.error(
      'A single repository action (LIST, GET, or LATEST) is required')


def main():
  """Main script function."""
  options, action = ParseArgs()
  log_helper.InitLogger(options)
  repo = ChromeRepo(options.repo_url, options.repo_build_id_pattern,
                    proxy_server=options.repo_proxy)
  try:
    if action == 'list':
      build_index = repo.GetBuildIndex()
      format_str = '%20s %30s'
      print format_str % ('Build ID', 'Last Modified')
      print format_str % ('-' * 16, '-' * 22)
      for build_id, timestamp, _sort_key in build_index:
        print format_str % (build_id, timestamp)
    elif action == 'latest':
      build_id, timestamp, subdir = repo.GetLatestBuildId()
      print '%s (%s, %s)' % (build_id, timestamp, subdir)
    elif action == 'get':
      print repo.DownloadBuild(options.repo_work_dir,
                               options.repo_build_id,
                               options.repo_build_subdir)
  except (NotFoundError, DownloadError), error:
    _LOGGER.error('%s', error)
    sys.exit(1)


if __name__ == '__main__':
  main()
