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
from google.appengine.ext import webapp
from model import client as client_db

class ClientHandler(webapp.RequestHandler):
  """A class to handle creating and querying clients."""

  def get(self, client_id):
    """Responds with information about clients.

    If a client_id is not specified, responds with a JSON encoded list of
    available clients. If a client_id is specified, responds with JSON encoded
    information about the client or a 404 if the client doesn't exist.

    Args:
      client_id: The client ID. May be an empty string.
    """
    if client_id:
      client = client_db.Client.get_by_key_name(client_id)
      if not client:
        self.error(404)  # Not found.
        return

      result = {'id': client.key().id_or_name(),
                'description': client.description}
    else:
      clients = client_db.Client.all()

      result = []
      for client in clients:
        result.append({'id': client.key().id_or_name(),
                       'description': client.description})

    self.response.headers['Content-Type'] = 'application/json'
    json.dump(result, self.response.out)

  def post(self, client_id):
    """Creates a new client.

    Adds a client to the data store. The ID and description should be specified
    as POST parameters in the request. Responds with a 200 on success or a 400
    if there are invalid parameters.

    Args:
      client_id: The client ID. Must be an empty string.
    """
    if client_id:
      self.error(400)  # Bad request.
      return

    id = self.request.get('id', None)
    desc = self.request.get('description', None)
    if not id or not desc:
      self.error(400)  # Bad request.
      return

    # Creates a new client or updates the description for an existing client.
    client = client_db.Client(key_name=id, description=db.Text(desc))
    client.put()
