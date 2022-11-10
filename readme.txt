#### Update Report IDs #####

to update reports - go to report/config.yml

###############################################


#### Delpoy code to Azure Web App ####
1. click Repos
2. click Set up build
3. choose Python to Linux Web App on Azure
4. choose Azure subscription and follow the steps
5. a yml will be generated
6. modify yml file
    #### set up a new feed before modify yml file ####
    6.1 click Artifacts on the left
    6.2 click Create feed and give a name to the new feed
    6.3 click connect to feed and go to the python section
    6.4 click twine to find the information needed
    6.5 follow the instruction to create a .pypirc file in the project folder
    6.6 go to the yml file and modify the scripts to
        python -m pip install --upgrade pip twine                                        
        python setup.py sdist bdist_wheel
    6.7 change artifact to the feed ceated eg. artifact: ford_dev
    6.8 change the package to link to the feed  eg.package: $(Pipeline.Workspace)/ford_dev/$(Build.BuildId).zip

7. set the config in azure web application 
    #### this setting allows azure web application to install the requirements needed for python project ####
    7.1 click the web application to deploy
    7.2 click Configuration
    7.3 click New application setting
    7.4 Set the name to 'SCM_DO_BUILD_DURING_DEPLOYMENT' and the Value to 'True'
8. run the Pipeline
