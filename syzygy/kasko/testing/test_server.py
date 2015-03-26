# Copyright 2014 Google Inc. All Rights Reserved.
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
import cgi
import msvcrt
import optparse
import os
import re
import struct
import sys
import tempfile
import uuid

def serve_file_handler(file_path):
  class ServeFileHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def __init__(self, request, client_address, socket_server):
      BaseHTTPServer.BaseHTTPRequestHandler.__init__(
        self, request, client_address, socket_server)

    def do_GET(self):
      f = open(file_path, 'rb')
      contents = f.read()
      self.send_response(200)
      self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
      self.end_headers()
      self.wfile.write(contents)
  return ServeFileHandler

def multipart_form_handler(incoming_directory):
  class MultipartFormHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def __init__(self, request, client_address, socket_server):
      BaseHTTPServer.BaseHTTPRequestHandler.__init__(
        self, request, client_address, socket_server)

    def do_POST(self):
      content_type, parameters = cgi.parse_header(
          self.headers.getheader('content-type'))
      if content_type != 'multipart/form-data':
        raise Exception('Unsupported Content-Type: ' + content_type)
      post_multipart = cgi.parse_multipart(self.rfile, parameters)
      if self.path == '/crash_failure':
        self.log_error('Simulating upload failure.')
        self.send_response(500)
        self.end_headers()
      elif self.path == '/crash':
        if len(incoming_directory):
          tempdir = tempfile.mkdtemp()
          for field, values in post_multipart.items():
            if re.match('^[a-zA-Z0-9_-]+$', field):
              file_path = os.path.join(tempdir, field)
              self.log_message('Writing %s', file_path)
              f = open(file_path, 'wb+')
              f.write(','.join(values))
              f.close()
          # Ensure that the entire directory appears atomically.
          # Technically we don't know for sure that the temporary directory is
          # on the same volume. It would be better if we did.
          report_id = str(uuid.uuid4())
          report_directory = os.path.join(incoming_directory, report_id)
          self.log_message('Renaming %s to %s', tempdir, report_directory)
          os.rename(tempdir, report_directory)
        else:
          self.log_error('ERROR: incoming_directory is unset.')
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(report_id)
      else:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        for field, values in post_multipart.items():
          self.wfile.write(field + '=' + ','.join(values) + '\r\n')
  return MultipartFormHandler

if __name__ == '__main__':
  option_parser = optparse.OptionParser()
  option_parser.add_option('--startup-pipe', type='int',
                           dest='startup_pipe',
                           help='File handle of pipe to parent process')
  option_parser.add_option('--incoming-directory',
                           dest='incoming_directory',
                           help='Path where uploaded files should be written')
  option_parser.add_option('--serve-file',
                           dest='serve_file',
                           help='Path to a file that should be served in '
                           'response to all requests')

  options, args = option_parser.parse_args()

  if options.serve_file:
    page_handler = serve_file_handler(options.serve_file)
  else:
    page_handler = multipart_form_handler(options.incoming_directory)

  server = BaseHTTPServer.HTTPServer(('127.0.0.1', 0), page_handler)

  print 'HTTP server started on http://127.0.0.1:%d...' % \
      (server.server_port)

  # Notify the parent that we've started. (BaseServer subclasses
  # bind their sockets on construction.)
  if options.startup_pipe is not None:
    fd = msvcrt.open_osfhandle(options.startup_pipe, 0)
    startup_pipe = os.fdopen(fd, "w")
    # Write the assigned port as an unsigned 2-byte value.  This
    # is _not_ using network byte ordering since the other end of the
    # pipe is on the same machine.
    startup_pipe.write(struct.pack('=H', server.server_port))
    startup_pipe.close()

  server.serve_forever()
