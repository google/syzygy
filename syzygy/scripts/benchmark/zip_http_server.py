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
import BaseHTTPServer
import SimpleHTTPServer
import posixpath
import sys
import urllib
import zipfile


def sanitize_path(path):
  """Sanitize a /-separated PATH.

  Components that mean special things (e.g. '..' and '.') are ignored.
  """
  # abandon query parameters and hash tag.
  path = urllib.splitquery(path)[0]
  path = urllib.splittag(path)[0]
  path = urllib.unquote(path)
  path = posixpath.normpath(path)
  words = path.split('/')
  words = filter(None, words)
  path = ''
  for word in words:
    if word in (posixpath.curdir, posixpath.pardir):
      continue
    path = posixpath.join(path, word)
  return path


class ZipFileRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
  """An HTTP request handler class that can serve from a zip archive.

  Note: the server must hava a function named zip_file(), returning
  the zip archive to serve from.
  """
  SuperClass = SimpleHTTPServer.SimpleHTTPRequestHandler

  def __init__(self, request, client_address, server):
    self._zip_file = server.zip_file()
    self.SuperClass.__init__(self, request, client_address, server)

  def send_head(self):
    """Common code for GET and HEAD commands.

    Override from SimpleHTTPRequestHandler.
    """
    path = sanitize_path(self.path)
    file_info = None
    file_object = None
    if path == '' or path.endswith('/'):
      path = posixpath.join('index.html')

    try:
      # Try and retrieve the info for the path, then open it.
      file_info = self._zip_file.getinfo(path)
      file_object = self._zip_file.open(file_info)
    except KeyError:
      self.send_error(404, "File not found")
      return None

    ctype = self.guess_type(path)
    self.send_response(200)
    self.send_header("Content-type", ctype)
    self.send_header("Content-Length", file_info.file_size)
    self.send_header("Last-Modified",
                     self.date_time_string_for_zipinfo(file_info))
    self.end_headers()
    return file_object

  def date_time_string_for_zipinfo(self, zipinfo):
    """Return the date and time for a ZipInfo formatted for a message header."""
    (year, month, day, hh, mm, ss) = zipinfo.date_time
    s = "%02d/%3s/%04d %02d:%02d:%02d" % (
                day, self.monthname[month], year, hh, mm, ss)
    return s


class HTTPZipFileServer(BaseHTTPServer.HTTPServer):
  """An HTTP server that serves from a zip archive."""
  def __init__(self, server_address, request_class, zip_file):
    BaseHTTPServer.HTTPServer.__init__(self,
                                       server_address,
                                       request_class)
    self._zip_file = zipfile.ZipFile(zip_file, 'r')

  def zip_file(self):
    """Returns the server's ZIP file."""
    return self._zip_file


def test(handler_class = ZipFileRequestHandler,
         server_class = HTTPZipFileServer,
         protocol="HTTP/1.0"):
  """Test the HTTP request handler class.

  This runs an HTTP server on port 8000 from the zip archive passed as
  the first argument.
  """
  zip_file = sys.argv[1]

  server_address = ('', 8000)

  handler_class.protocol_version = protocol
  httpd = server_class(server_address, handler_class, zip_file)

  sa = httpd.socket.getsockname()
  print "Serving HTTP on", sa[0], "port", sa[1], "..."
  httpd.serve_forever()


if __name__ == '__main__':
  test()
