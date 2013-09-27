#!python
# Copyright 2013 Google Inc. All Rights Reserved.
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

import json
import optparse
import sys
import threading
import urlparse
import zip_http_server


# The set of address values that map to 'localhost'.
_LOCALHOST_ADDRESSES = (None, '', '0.0.0.0', '127.0.0.1')


class RequestHandler(zip_http_server.ZipFileRequestHandler):
  """A request handler class that handles incoming JSON post requests by
  storing the metrics and shutting down the server."""

  def do_POST(self):
    """A handler for the POST method."""
    post_body = None
    try:
      # Read the posted content.
      content_len = int(self.headers.getheader('content-length'))
      post_body = self.rfile.read(content_len)

      # The json is packed into a data argument.
      data = urlparse.parse_qs(post_body)['data'][0]

      # Stash the metrics in the server.
      results = json.loads(data)
      self.server.SetResults(results)

      # Send back a plain-text version of the data.
      pretty_data = json.dumps(results, sort_keys=True, indent=2)
      self.send_response(200)
      self.send_header('Content-Type', 'text/plain')
      self.send_header('Content-Length', len(pretty_data))
      self.end_headers()
      self.wfile.write(pretty_data)
    except Exception, error:
      message = str(error)
      self.send_response(400)
      self.send_header('Content-Type', 'text/plain')
      self.send_header('Content-Length', len(message))
      self.end_headers()
      self.wfile.write(message)


class DromaeoServer(zip_http_server.HTTPZipFileServer):
  """This class implements a runnable HTTP server that serves the dromaeo
  benchmark from a ZIP archive.
  """
  def __init__(self, zip_file, address='', port=0, request_handler_class=None):
    # Use the default request handler if no over-ride is specified.
    if request_handler_class is None:
      request_handler_class = RequestHandler

    # Initialize the base class.
    server_address = (address, port)
    zip_http_server.HTTPZipFileServer.__init__(
        self, server_address, request_handler_class, zip_file)

    # The results and an event to track when they get set.
    self._results = None
    self._results_have_been_set = threading.Event()

  def Run(self):
    """Runs the HTTP server in a background thread."""
    thread = threading.Thread(target=self.serve_forever)
    thread.daemon = True
    thread.start()

  def SetResults(self, results):
    """Stores the results of the benchmark and sets an event to notify any other
    thread waiting on the results.
    """
    self._results = results
    self._results_have_been_set.set()

  def HasResults(self):
    """Returns true if the results have been set."""
    return self._results is not None

  def GetResults(self):
    """Returns the results or None."""
    return self._results

  def WaitForResults(self, timeout):
    """Blocks until results have been set, or the timeout duration elapses."""
    self._results_have_been_set.wait(timeout)

  def Reset(self):
    """Resets the event notification of the results being set."""
    self._results_have_been_set.clear()

  def GetUrl(self):
    """Returns the URL at which the dromaeo benchmark is running."""
    address, port = self.server_address
    if address in _LOCALHOST_ADDRESSES:
      address = 'localhost'
    return 'http://%s:%d/?dom&automated&post_json' % (address, port)

  def FormatResultsAsText(self):
    """Prints a dromaeo result set in a nicely human readable format."""
    if not self.HasResults():
      return 'None'
    sorted_results = sorted(self._results.iteritems())
    return '\n'.join('  %s : %s' % kv for kv in sorted_results)


def main(argv):
  # Setup the argument parser.
  parser = optparse.OptionParser()
  parser.add_option('-a', '--address', default='', help='The address to bind.')
  parser.add_option('-p', '--port', type='int', default=0,
                    help='The port to bind (by default, the server will '
                         'randomly select an available port).')
  parser.add_option('-z', '--zip-file', default='./dramaeo.zip',
                    help='The zipfile containing the dramaeo resources '
                         '(default: %default).')
  parser.add_option('-t', '--timeout', type='int', default=300,
                    help='The maximum time to wait for results, in seconds'
                         '(default: %default).')

  # Parse the arguments.
  options, extra = parser.parse_args(argv)
  if extra:
    parser.error('Unexpected arguments: %s' % extra)

  # Create the server.
  server = DromaeoServer(zip_file=options.zip_file,
                         address=options.address,
                         port=options.port)

  # Run the server in another thread.
  print "Starting dromaeo server."
  server.Run()
  print "URl: %s" % server.GetURL()
  try:
    server.WaitForResults(options.timeout)
  except KeyboardInterrupt:
    pass
  server.shutdown()

  # Print the results to the console.
  if not server.HasResults():
    print "Timed out or interrupted while waiting for results."
    return 1
  else:
    print server.FormatResultsAsText()


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
