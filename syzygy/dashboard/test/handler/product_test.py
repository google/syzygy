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

import httplib
import json
from handler import product
from model import client as client_db
from model import product as product_db
from test.handler import handler_test


# Ignore member variables being set outside of __init__.
# pylint: disable=W0201
class ProductTest(handler_test.TestCase):

  def setUp(self):
    super(ProductTest, self).setUp()

    # Insert values into the db.
    p1 = product_db.Product(key_name='p1')
    p1.put()
    client_db.Client(key_name='c1', parent=p1, description='c1_desc').put()

    product_db.Product(key_name='p2').put()

  def _InitHandler(self, input_data):
    self._handler = product.ProductHandler()
    super(ProductTest, self)._InitHandler(self._handler, input_data)

  def testGetAll(self):
    self._InitHandler('')
    self._handler.get('')
    self.assertEqual(httplib.OK, self._response.status)

    result = json.loads(self._response.out.getvalue())
    self.assertEqual(
        {'products': [
            {'product_id': 'p1'},
            {'product_id': 'p2'}
        ]},
        result)

  def testGetById(self):
    self._InitHandler('')
    self._handler.get('p1')
    self.assertEqual(httplib.OK, self._response.status)

    result = json.loads(self._response.out.getvalue())
    self.assertEqual(
        {'product_id': 'p1',
         'client_ids': ['c1']},
        result)

  def testGetArgValidation(self):
    # Non-existing product ID.
    self._InitHandler('')
    self._handler.get('blah')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

  def testPost(self):
    self._InitHandler('product_id=p3')
    self._handler.post('')
    self.assertEqual(httplib.CREATED, self._response.status)

    self.assertTrue(product_db.Product.get_by_key_name('p3') is not None)

  def testPostArgValidation(self):
    # Product ID in URL.
    self._InitHandler('product_id=p3')
    self._handler.post('p3')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Product ID missing from body.
    self._InitHandler('')
    self._handler.post('')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Existing product ID.
    self._InitHandler('product_id=p1')
    self._handler.post('')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

  def testPut(self):
    self._InitHandler('')
    self._handler.put()
    self.assertEqual(httplib.METHOD_NOT_ALLOWED, self._response.status)

  def testDelete(self):
    self._InitHandler('')
    self._handler.delete('p1')
    self.assertEqual(httplib.OK, self._response.status)

    self.assertTrue(product_db.Product.get_by_key_name('p1') is None)

  def testDeleteArgValidation(self):
    # Product ID missing from body.
    self._InitHandler('')
    self._handler.delete('')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Non-existing product ID.
    self._InitHandler('')
    self._handler.delete('blah')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)
