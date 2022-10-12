# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from flask import current_app as app
import json
import requests

class AadService:

    def get_access_token():
        '''Generates and returns Access token

        Returns:
            string: Access token
        '''

        response = None
        try:
            if app.config['AUTHENTICATION_MODE'].lower() == 'serviceprincipal':

                token_url = ('https://login.microsoftonline.com/'+app.config['TENANT_ID']+'/oauth2/token')
                data = {"client_id": app.config['CLIENT_ID'],
                        "client_secret": app.config['CLIENT_SECRET'],
                        "grant_type": "client_credentials",
                        "resource": "https://analysis.windows.net/powerbi/api",
                        "scope": app.config['SCOPE']}

                token_response = json.loads(requests.post(token_url, data=data).text)

                try:
                    return token_response['access_token']
                except KeyError:
                    raise Exception(response['error_description'])
        except Exception as ex:
            raise Exception('Error retrieving Access token\n' + str(ex))