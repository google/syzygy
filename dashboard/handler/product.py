# Copyright 2011 Google Inc.
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
from google.appengine.ext import db
from google.appengine.ext import webapp
from model import client as client_db
from model import product as product_db

class ProductHandler(webapp.RequestHandler):
  """A class to handle creating and querying products."""

  def get(self, product_id):
    """Responds with information about a product.

    Responds with a JSON encoded product ID and client IDs for a given
    product_id. If the product doesn't exist, responds with a 404.

    Args:
      product_id. The product ID.
    """
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(404)  # Not found.
      return

    client_keys = client_db.Client.all(keys_only=True)
    client_keys.ancestor(product)
    client_ids = [key.name() for key in client_keys]

    result = {'product_id': product.key().name(),
              'client_ids': client_ids}

    self.response.headers['Content-Type'] = 'application/json'
    json.dump(result, self.response.out)

  def post(self, product_id):
    """Creates a new product.

    Adds a product to the data store. The product ID should be specified in the
    URL. Responds with a 200 on success or a 400 if there are invalid
    parameters.

    Args:
      product_id: The product ID.
    """
    # Creates a new client or updates the description for an existing client.
    product = product_db.Product(key_name=product_id)
    product.put()
