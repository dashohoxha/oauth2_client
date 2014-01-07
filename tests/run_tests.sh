#!/bin/bash

### get the path of profiles and contributed modules
path=$(pwd)
profiles=${path//\/btranslator*} 
contrib=${path//\/oauth2_client*}

### copy the modules that will be installed during the test to the profile 'testing'
for module in oauth2_client oauth2_server entity entityreference xautoload ctools
do 
    ln -sf $contrib/$module $profiles/testing/modules/
done

### run the tests
drush test-clean
drush test-run OAuth2ClientTestCase
