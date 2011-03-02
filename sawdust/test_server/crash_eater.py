#!/usr/bin/python2.5
#
# Copyright 2010 Google Inc. All Rights Reserved.
"""A local server implementation for testing Sawdust. It consumes crash (and
log uploads pretty much as Google crash server would. It has the same POST
semantics, accepts and stores uploaded files. These files can be then either
found on the file system or downloaded.
The purpose is to quickly check if upload command works without polluting the
real crash server.
"""

__author__ = 'motek@google.com (Marcin Swiatek)'

import anydbm
import BaseHTTPServer
import bisect
import cgi
import datetime
import optparse
import os
import cPickle as pickle
import shutil
import SocketServer
import stat
import cStringIO as StringIO
import sys
import tempfile
import urllib
import urlparse

PROTOCOL_VERSION = 'HTTP/1.1'
UPLOAD_PATH = 'cr/report'


class HTTPServer(SocketServer.ThreadingTCPServer):
  allow_reuse_address = 1  # Seems to make sense in testing environment.


class Error(Exception):
  pass


def GetParser():
  parser = optparse.OptionParser(usage='%prog [directory] [options]')
  parser.add_option('-n', '--server', dest='server', metavar='NAME',
                   type='string', default='localhost',
                   help='The name to serve under.')
  parser.add_option('-p', '--port', dest='port', metavar='ID',
                   type='int', default=8080,
                   help='Port to use.')
  return parser


def CautiousCopy(fsrc, fdst, length):
  remaining_length = length
  while remaining_length > 0:
    buf = fsrc.read(remaining_length)
    if buf:
      fdst.write(buf)
    remaining_length -= len(buf)


class LogStorage(object):
  """Manages the directory of uploaded log files."""
  INDEX_FILE_NAME = "index.db"
  DATA_FILE_SUFFIX = "logs.zip"

  def __init__(self, work_directory):
    """Initializes content based on the content of work_directory.

    If the directory does not exist, we will try to create it.
    If the index file does not exist, again we will try to create it.
    """
    if not os.path.exists(work_directory):
      os.makedirs(work_directory)
      self._new_dir = True
    elif not os.path.isdir(work_directory):
      raise Error(work_directory + ' exists but is not a directory')
      self._new_dir = False

    self.StorageLocation = work_directory
    self.IndexFile = anydbm.open(os.path.join(self.StorageLocation,
                                              self.INDEX_FILE_NAME), 'c')
    self.Index = self._BuildIndex()

  def BashAll(self):
    pass

  def AddNew(self, meta_data, data, length):
    """Inserts a new entry (with binary data and all) into the structure.

    The new entry shall be:
      (a) stamped with the current time;
      (b) written out to a disk file (watch the length);
      (c) added to the disk index;
      (d) added to the in-memory sorted list.
    Note that this routine cannot handle multi-part messages.
    Args:
      meta_data: A dictionary describing the original request.
      data: A file with content.
      length: Content length to be read/copied from the file.
    """
    # meta_data will map a string key to a list of entries. Our syntax basically
    # takes string-->string, so we will flatten the dictionary right here.
    description = dict((str(k), str(v[0])) for (k, v) in meta_data.iteritems())
    description['time'] = datetime.datetime.now()
    file_info = None
    tgt_file = None
    process_succeeded = False
    try:
      name_suffix = "." + self.DATA_FILE_SUFFIX
      name_prefix = description['prod'] + "_"
      file_info = tempfile.mkstemp(suffix=name_suffix, prefix=name_prefix,
                                   dir=self.StorageLocation)
      new_key = os.path.split(file_info[1])[-1][:-len(name_suffix)]
      id_info_tuple = self._FormTuple(description, new_key)
      tgt_file = os.fdopen(file_info[0], "wb")

      CautiousCopy(data, tgt_file, length)
      self.IndexFile[new_key] = pickle.dumps(description)
      bisect.insort(self.Index, id_info_tuple)
      process_succeeded = True
      return True, new_key
    except (OSError, IOError):
      return False, "Tragically failed to insert."
    finally:
      # At the end, close the file. However, since a file can have two
      # representations, a bit of extra code is requried.
      if tgt_file is not None:
        tgt_file.close()
      elif file_info is not None:
        os.close(file_info[0])
      if not process_succeeded and file_info is not None:
        os.remove(file_info[1])

  def GetAllEntries(self):
    """Returns an iterator over a collection of (dictionary, reference_key).

    Dictionary contains user-friendly things to show. You can use reference_key
    in GetFile.
    """
    return ((e[-1], e[-2]) for e in self.Index)

  def GetFile(self, file_key):
    """Returns read-only stream with data. Please close it once done."""

    full_file_name = os.path.join(self.StorageLocation,
                                  "%s.%s" % (file_key, self.DATA_FILE_SUFFIX))
    return open(full_file_name, "rb")

  def HasEntry(self, key):
    return key in self.IndexFile

  def _BuildIndex(self):
    """Create the index from index file.

    The index kept around is a sorted list of tuples of known columns, rather
    than a dictionary.
    """
    # The iterator expression will unpack key, value pairs. The key is
    # always the file title, while the value is a dictionary pickled to a
    # string. That dictionary must contain following fields: prod, ver, time.
    # Other are optional.
    all_data_iter = ((fn, pickle.loads(pickled)) for (fn, pickled) in
                     self.IndexFile.iteritems())
    return sorted(self._FormTuple(dct, fn) for (fn, dct) in all_data_iter)

  @staticmethod
  def _FormTuple(meta_data_dict, file_name):
    return (meta_data_dict['prod'], meta_data_dict['ver'],
            meta_data_dict['time'], file_name, meta_data_dict)

  def Close(self):
    self.IndexFile.close()
    self.Index = None


class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  def do_GET(self):
    resource_path = urllib.unquote_plus(self.path).lstrip('/\\')
    f = None
    if not resource_path or resource_path in ('index', 'index.html'):
      f = self.SendTocStreamHead()
    elif self.server.Storage.HasEntry(resource_path):
      try:
        f = self.server.Storage.GetFile(resource_path)
        fs = os.fstat(f.fileno())
        file_size = fs[stat.ST_SIZE]
        self.send_response(200)
        self.send_header('Content-type', 'application/zip')
        self.send_header('Content-Length', str(file_size))
        self.send_header('Last-Modified', self.date_time_string(fs.st_mtime))
        self.send_header('Content-Disposition',
                         'attachment; filename=LogData.zip')
        self.end_headers()
      except IOError:
        f = None  # This is not good, this file ought to be there.

    if f:
      shutil.copyfileobj(f, self.wfile)
      f.close()
    else:
      self.send_error(404, "File not found")

  def do_POST(self):
    resource_id = urllib.unquote_plus(self.path).lstrip('/\\')
    resource_id = urlparse.urlsplit(resource_id)
    resource_query =  urlparse.parse_qs(resource_id.query)
    if self.headers.type == 'multipart/form-data':
      # This is an assumption check. I might need to handle this type if we
      # ever run into this exception.
      raise NotImplementedError(self.headers.type + ' not handled.')

    if not 'content-length' in self.headers:
      return

    data_len = int(self.headers['content-length'])
    status, key = self.server.Storage.AddNew(resource_query, self.rfile,
                                             data_len)
    self.send_response(201)
    self.end_headers()

    self.wfile.write('<HTML>POST ')
    if status:
      self.wfile.write('OK. <BR>')
      self.wfile.write(key)
      self.wfile.write('<BR>')
    else:
      self.wfile.write('FAILED')

    # Read and processed - done (reading from this connection on windows will
    # likely hang the program).
    self.close_connection = 1

  def SendTocStreamHead(self):
    """Sending the table of content."""
    all_data = list(self.server.Storage.GetAllEntries())
    f = StringIO.StringIO()
    displaypath = cgi.escape(urllib.unquote(self.path))
    f.write('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
    f.write('<html>\n<title>Directory listing for CrashEater</title>\n')

    if all_data:
      f.write('<body>\n<h2>Directory listing for CrashEater</h2>\n')
      f.write('<table border="1">\n')
      for (dct, link) in all_data:
        date = dct['time'].strftime('%Y-%m-%d %H:%M')
        application = dct['prod']
        version = dct['ver']
        f.write('<tr>\n')
        f.write('<th>%s</th>\n' % application)
        f.write('<th>%s</th>\n' % version)
        f.write('<th><a href="%s">%s</a></th>\n' % (urllib.quote(link), date))
        f.write('</tr>\n')
      f.write('</table>\n')
    else:
      f.write('<body>\n<h2>The directory of CrashEater is empty right'
              ' now</h2>\n')

    f.write("</body>\n</html>\n")
    length = f.tell()
    f.seek(0)
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", str(length))
    self.end_headers()
    return f


class HttpServerWithContent(HTTPServer):
  def __init__(self, host_name, port, content_handler):
    RequestHandler.protocol_version = PROTOCOL_VERSION
    assert content_handler is not None
    self.Storage = content_handler
    HTTPServer.__init__(self, (host_name, port), RequestHandler)


def main():
  (command_options, args) = GetParser().parse_args()
  work_directory = os.curdir if not args else args[0]

  # Just start the server.
  data = LogStorage(work_directory)
  try:
    server = HttpServerWithContent(command_options.server,
                                   command_options.port, data)
    print "Press Ctrl+C to quit..."
    server.serve_forever()
  except KeyboardInterrupt:
    server.socket.close()
  finally:
    data.Close()

if __name__ == "__main__":
  sys.exit(main())
