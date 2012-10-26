#!/usr/bin/python2.4
#
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

"""Unit tests for the chrome_repo module."""

# Standard Modules:
import contextlib
import cStringIO
import datetime
import os
import re
import shutil
import tempfile
import unittest
import zipfile

# Local Modules:
import chrome_repo

# pylint: disable=C0103,R0904,W0212
#   C0103 -> Naming conventions for methods.
#   R0904 -> Too many public methods.
#   W0212 -> Access to protected members.


# Sample XML output from an official build repository.
VALID_XML_INDEX = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
  <html>
   <head>
    <title>Index of /official_builds</title>
   </head>
   <body>
  <h1>Index of /official_builds</h1>
  <table><tr><th><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr><tr><th colspan="5"><hr></th></tr>
  <tr><td valign="top"><img src="/icons/back.gif" alt="[DIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
  <tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="9.0.597.98/">9.0.597.98/</a></td><td align="right">18-Mar-2011 18:06  </td><td align="right">  - </td><td>&nbsp;</td></tr>
  <tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="9.0.597.99/">9.0.597.99/</a></td><td align="right">19-Mar-2011 01:07  </td><td align="right">  - </td><td>&nbsp;</td></tr>
  <tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="9.0.597.100/">9.0.597.100/</a></td><td align="right">19-Mar-2011 01:08  </td><td align="right">  - </td><td>&nbsp;</td></tr>
  <tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="10.0.1.1/">10.0.1.1/</a></td><td align="right">19-Mar-2011 01:08  </td><td align="right">  - </td><td>&nbsp;</td></tr>
  </td><td>&nbsp;</td></tr>
  <tr><th colspan="5"><hr></th></tr>
  </table>
  <address>Apache/2.2.14 (Ubuntu) Server at some.host.net Port 80</address>
  </body></html>"""


def _IndexEntry(build_id, timestamp):
  """Creates a build index entry from an id and timestamp."""
  sort_key = (timestamp,) + tuple(int(i) for i in build_id.split('.'))
  return build_id, timestamp, sort_key


# Sorted list of build_id, timestamp pairs for the above XML sample.
VALID_INDEX_OUTPUT = [
    _IndexEntry('10.0.1.1', datetime.datetime(2011, 03, 19, 1, 8)),
    _IndexEntry('9.0.597.100', datetime.datetime(2011, 03, 19, 1, 8)),
    _IndexEntry('9.0.597.99', datetime.datetime(2011, 03, 19, 1, 7)),
    _IndexEntry('9.0.597.98', datetime.datetime(2011, 03, 18, 18, 6)),
    ]


class TestHTTPConnection(object):
  """Mocks an HTTPConnection (and HTTPSConnection) object and response.

  Attributes:
    status: The status to return on a request.
    headers: The headers to return on a request.
  """

  def  __init__(self, status, body, headers=None):
    """Initialize an TestHTTPConnection instance.

    Args:
      status: The status to return on a request.
      body: The body to return on a request.
      headers: The headers to return on a request.
    """
    self.status = status
    self.msg = headers or []
    self._body = body
    self._read_completed = False

  def __call__(self, *_args, **_kwargs):
    """Stubs the HTTPConnection.__init__() method."""
    return self

  def request(self, *_args, **_kwargs):
    """Pretends to do a request."""
    pass

  def getresponse(self):
    """Pretends to return a response object."""
    return self

  def read(self, *_args, **_kwargs):
    """Returns the body of the response.

    To facilitate reuse of the connection factory object, this function
    alternates between returning the actual body (for consumption by the
    caller) and returning None (signaling that the entire body has been
    read).
    """
    if self._read_completed:
      self._read_completed = False
      return None
    self._read_completed = True
    return self._body

  def close(self):
    """Pretends to close the connection."""
    pass


class TestChromeRepo(unittest.TestCase):
  """Unit tests for the chrome_repo module."""

  def testConstructor(self):
    # Ensures invalid constructor parameters generate appropriate errors.
    self.assertRaises(
        ValueError, chrome_repo.ChromeRepo, 'ftp://foo.bar.net/blah')
    self.assertRaises(
        ValueError, chrome_repo.ChromeRepo, 'asdfasdfasdfa')
    self.assertRaises(
        re.error, chrome_repo.ChromeRepo, 'http://foo.bar.net/blah', '(')

  def testGetFilePath(self):
    # TODO(rogerm): Get these unittests back in sync with the code.
    # The following code is commented out because it no longer matches the
    # signature of the API.
    pass

    # Ensures file paths inside the repo are calculated correctly.
    #repo = chrome_repo.ChromeRepo('http://foo.bar.net/blah')
    #build_id = 'NNNNN'
    #relative_path = 'some/path/to/a/file.txt'
    #self.assertEquals(
    #    '/blah/%s/win/%s' % (build_id, relative_path),
    #    repo._GetFilePath(build_id, relative_path))

  def testPerformRequest(self):
    # Ensures that the basic HTTP request handling utility works.
    repo_url = 'http://foo.bar.net'
    test_path = '/path'
    expected_body = 'This is just a test'
    expected_status = 200
    expected_headers = {'Content-Type' : 'text/plain'}
    expected_url = repo_url + test_path
    repo = chrome_repo.ChromeRepo(repo_url + '/blah')
    repo._connection_factory = TestHTTPConnection(
        expected_status, expected_body, expected_headers)
    out_stream = cStringIO.StringIO()
    out_status, out_headers, out_url = repo._PerformRequest('GET', test_path,
                                                            out_stream)
    self.assertEquals(expected_status, out_status)
    self.assertEquals(expected_headers, out_headers)
    self.assertEquals(expected_url, out_url)
    self.assertEquals(expected_body, out_stream.getvalue())

  def testGetBuildIndexOnServerError(self):
    # Ensures that server errors generate an exception.
    repo = chrome_repo.ChromeRepo('http://foo.bar.net/blah')
    repo._connection_factory = TestHTTPConnection(500, '', {})
    self.assertRaises(chrome_repo.DownloadError, repo.GetBuildIndex)

  def testGetValidBuildIndex(self):
    # Ensures that the build index parsing works.
    repo = chrome_repo.ChromeRepo('http://foo.bar.net/blah')
    repo._connection_factory = TestHTTPConnection(200, VALID_XML_INDEX, {})
    self.assertEquals(VALID_INDEX_OUTPUT, repo.GetBuildIndex())

  def testGetInvalidBuildIndex(self):
    # Checks that build index parsing doesn't match bad input.
    repo = chrome_repo.ChromeRepo('http://foo.bar.net/blah')
    repo._connection_factory = TestHTTPConnection(200, 'blah, blah', {})
    self.assertEquals([], repo.GetBuildIndex())

  def testLatestBuildId(self):
    # Checks that extracting the lastest complete build id works.
    repo = chrome_repo.ChromeRepo('http://foo.bar.net/blah')
    repo._connection_factory = TestHTTPConnection(200, VALID_XML_INDEX, {})
    self.assertEquals(VALID_INDEX_OUTPUT[0][:2], repo.GetLatestBuildId())

  def _DoDownloadTest(self, use_real_size):
    """Performs a download, varying whether or not the file size is correct.

    Args:
      use_real_size: If False, the Content-Length header will be set such
          that it does not match the actual size of the data returned in
          the mocked HTTP response.
    """
    work_dir = tempfile.mkdtemp()
    try:
      repo = chrome_repo.ChromeRepo('http://foo.bar.net/blah')
      content = 'this is some text'
      data_file_path = os.path.join(work_dir, 'data.txt')
      with open(data_file_path, 'w') as data_file:
        data_file.write(content)

      zip_file_path = os.path.join(work_dir, 'temp.zip')
      with contextlib.closing(zipfile.ZipFile(zip_file_path, 'w')) as zip_file:
        zip_file.write(
            data_file_path,
            os.path.join('chrome-win32', os.path.basename(data_file_path)))

      content_length = os.stat(zip_file_path).st_size
      if not use_real_size:
        content_length += 100
      with open(zip_file_path, 'rb') as zip_file:
        repo._connection_factory = TestHTTPConnection(
            200, zip_file.read(), {'Content-Length' : str(content_length)})

      os.remove(zip_file_path)
      os.remove(data_file_path)

      build_id = 'NNNN'
      chrome_dir = repo.DownloadBuild(work_dir, build_id)
      self.assertEquals(
          chrome_dir, os.path.join(work_dir, build_id, 'chrome-win32'))

      data_file_path = os.path.join(
          chrome_dir, os.path.basename(data_file_path))
      self.assertEquals(content, open(data_file_path).read())
    finally:
      shutil.rmtree(work_dir, ignore_errors=True)

  def testDownloadBuild(self):
    # Performs the basic download build test.
    self._DoDownloadTest(use_real_size=True)

  def testDownloadBuildBadSize(self):
    # Ensures that size mismatch between header and body generates exceptions.
    self.assertRaises(
        chrome_repo.DownloadError, self._DoDownloadTest, use_real_size=False)

  def testDownloadBuildNotFound(self):
    # Ensures that missing files on download generate an exception.
    work_dir = tempfile.mkdtemp()
    try:
      repo = chrome_repo.ChromeRepo('http://foo.bar.net/blah')
      repo._connection_factory = TestHTTPConnection(404, '', {})
      self.assertRaises(
          chrome_repo.NotFoundError, repo.DownloadBuild, work_dir, 'foo')
    finally:
      shutil.rmtree(work_dir, ignore_errors=True)

  def testDownloadBuildServerError(self):
    # Ensures that server errors on download generate an exception.
    work_dir = tempfile.mkdtemp()
    try:
      repo = chrome_repo.ChromeRepo('http://foo.bar.net/blah')
      repo._connection_factory = TestHTTPConnection(500, '', {})
      self.assertRaises(
          chrome_repo.DownloadError, repo.DownloadBuild, work_dir, 'foo')
    finally:
      shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == '__main__':
  unittest.main()
