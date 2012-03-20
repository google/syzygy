#!python
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

import StringIO
import unittest
from google.appengine.ext import testbed
from google.appengine.ext import webapp

class TestCase(unittest.TestCase):
  """Base class for handler unit tests."""

  def setUp(self):
    self._testbed = testbed.Testbed()
    self._testbed.activate()
    self._testbed.init_datastore_v3_stub()

  def tearDown(self):
    self._testbed.deactivate()

  def _InitHandler(self, handler, input):
    """Create fake request, response and handler."""
    self._request = webapp.Request({
        'wsgi.input': StringIO.StringIO(input),
        'CONTENT_LENGTH': len(input),
        'REQUEST_METHOD': 'POST'})
    self._response = webapp.Response()

    handler.initialize(self._request, self._response)
