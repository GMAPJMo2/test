# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from report.services.aadservice import AadService
from report.models.reportconfig import ReportConfig
from report.models.embedtoken import EmbedToken
from report.models.embedconfig import EmbedConfig
from flask import abort
import requests
import json

class PbiEmbedService:

    def get_embed_params_for_single_report(self, workspace_id, report_id,user,role_data):
        '''Get embed params for a report and a workspace

        Args:
            workspace_id (str): Workspace Id
            report_id (str): Report Id
            additional_dataset_id (str, optional): Dataset Id different than the one bound to the report. Defaults to None.

        Returns:
            EmbedConfig: Embed token and Embed URL
        '''

        user = user
        datasets = []
        role = role_data
        report_id = report_id

        report_url = f'https://api.powerbi.com/v1.0/myorg/groups/{workspace_id}/reports/'+report_id
        print(report_url)
        api_response = requests.get(report_url, headers=self.get_request_header())
        print(api_response)

        if api_response.status_code != 200:
            abort(api_response.status_code, description=f'Error while retrieving Embed URL\n{api_response.reason}:\t{api_response.text}\nRequestId:\t{api_response.headers.get("RequestId")}')

        api_response = json.loads(api_response.text)
        report = ReportConfig(api_response['id'], api_response['name'], api_response['embedUrl'])
        dataset_ids = api_response['datasetId']
        print(dataset_ids)

        datasets.append(dataset_ids)

        post_data = \
            str({
                "accessLevel": "View",
                "allowSaveAs": "false",
                "identities": [{
                    "username": user,
                    "roles": role,
                    "datasets": datasets
                }]
            })

        embededtoken_url=f'https://api.powerbi.com/v1.0/myorg/groups/{workspace_id}/reports/'+report_id+'/GenerateToken'

        api_response = requests.post(embededtoken_url,data=post_data, headers=self.get_request_header())
        print(api_response)
        print(datasets)

        if api_response.status_code != 200:
            abort(api_response.status_code,
                  description=f'Error while retrieving Embed token\n{api_response.reason}:\t{api_response.text}\nRequestId:\t{api_response.headers.get("RequestId")}')

        api_response = json.loads(api_response.text)
        embed_token = EmbedToken(api_response['tokenId'], api_response['token'], api_response['expiration'])

        embed_config = EmbedConfig(embed_token.tokenId, embed_token.token, embed_token.tokenExpiry, [report.__dict__])
        return json.dumps(embed_config.__dict__)

    def get_request_header(self):
        '''Get Power BI API request header

        Returns:
            Dict: Request header
        '''

        print(AadService.get_access_token())

        return {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + AadService.get_access_token()}
