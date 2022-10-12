# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

class BaseConfig(object):

    # Can be set to 'MasterUser' or 'ServicePrincipal'
    AUTHENTICATION_MODE = 'ServicePrincipal'

    # Workspace Id in which the report is present
    WORKSPACE_ID = 'd4dc7060-417f-4105-9771-2faa7181ada9'
    
    # Report Id for which Embed token needs to be generated
    REPORT_ID = ''
    
    # Id of the Azure tenant in which AAD app and Power BI report is hosted. Required only for ServicePrincipal authentication mode.
    TENANT_ID = 'c3dbf3ee-c71c-421c-833e-bb6f597dadba'
    
    # Client Id (Application Id) of the AAD app
    CLIENT_ID = '863acf43-7af8-4c32-8b36-2ce70a9deb56'
    
    # Client Secret (App Secret) of the AAD app. Required only for ServicePrincipal authentication mode.
    CLIENT_SECRET = '3fTVNKmh8~BkJf7c0h-9yfg~q.4FdvU5GH'
    
    # Scope of AAD app. Use the below configuration to use all the permissions provided in the AAD app through Azure portal.
    SCOPE = ['https://analysis.windows.net/powerbi/api/.default']
    
    # URL used for initiating authorization request
    AUTHORITY = 'https://login.microsoftonline.com/organizations'
    
    # Master user email address. Required only for MasterUser authentication mode.
    POWER_BI_USER = ''
    
    # Master user email password. Required only for MasterUser authentication mode.
    POWER_BI_PASS = ''
