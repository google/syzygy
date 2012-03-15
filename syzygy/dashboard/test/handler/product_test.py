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

import httplib
import json
import StringIO
import unittest
from google.appengine.ext import testbed
from google.appengine.ext import webapp
from handler import product
from model import client as client_db
from model import product as product_db

class ProductTest(unittest.TestCase):

  def setUp(self):
    # Set up the test bed.
    self._testbed = testbed.Testbed()
    self._testbed.activate()
    self._testbed.init_datastore_v3_stub()

    # Insert values into the db.
    p1 = product_db.Product(key_name='p1')
    p1.put()
    client_db.Client(key_name='c1', parent=p1, description='c1_desc').put()

    product_db.Product(key_name='p2').put()

  def tearDown(self):
    self._testbed.deactivate()

  def _Init(self, input):
    """Create fake request, response and handler."""
    self._request = webapp.Request({
        'wsgi.input': StringIO.StringIO(input),
        'CONTENT_LENGTH': len(input),
        'REQUEST_METHOD': 'POST'})
    self._response = webapp.Response()

    self._handler = product.ProductHandler()
    self._handler.initialize(self._request, self._response)

  def testGetAll(self):
    self._Init('')
    self._handler.get('')
    self.assertEqual(httplib.OK, self._response.status)
    result = json.loads(self._response.out.getvalue())
    products = result.get('products')
    self.assertEqual(2, len(products))
    self.assertEqual('p1', products[0].get('product_id'))
    self.assertEqual('p2', products[1].get('product_id'))

  def testGetByID(self):
    self._Init('')
    self._handler.get('p1')
    self.assertEqual(httplib.OK, self._response.status)
    result = json.loads(self._response.out.getvalue())
    self.assertEqual('p1', result.get('product_id'))
    self.assertEqual(['c1'], result.get('client_ids'))

  def testGetArgValidation(self):
    self._Init('')
    self._handler.get('blah')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

  def testPost(self):
    self._Init('product_id=p3')
    self._handler.post('')
    self.assertEqual(httplib.CREATED, self._response.status)

  def testPostArgValidation(self):
    self._Init('')
    self._handler.post('p1')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    self._Init('')
    self._handler.post('')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    self._Init('product_id=p1')
    self._handler.post('')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

  def testPut(self):
    self._Init('')
    self._handler.put()
    self.assertEqual(httplib.METHOD_NOT_ALLOWED, self._response.status)

  def testDelete(self):
    self._Init('')
    self._handler.delete('p1')
    self.assertEqual(httplib.OK, self._response.status)
    self.assertEqual(None, product_db.Product.get_by_key_name('p1'))

  def testDeleteArgValidation(self):
    self._Init('')
    self._handler.delete('')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    self._Init('')
    self._handler.delete('blah')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)
