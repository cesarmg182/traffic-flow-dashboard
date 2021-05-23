from __future__ import print_function
import sys
#import authenticate,assets,write_text,labels,agents,write_excel,incidents,labels2,networklog
import os
import re
import timeit
import test
from .authenticate import auth_get_token
from typing import List  ############

#import authenticate.auth_get_token

#os.chdir(r'C:\Python27\Scripts\acceso')

#token=authenticate.auth_get_token()   # get the token

#
#json_assets=assets.get_assests_test(token)   # get assets states
#json_assets=assets.get_assests_test(token)  
#write_text.write_assests_file(json_assets)   
#write_text.write_json_file(json_assets) 
#
#json_agents=agents.get_agents_status(token)   
#write_text.write_json_file(json_agents)  
#
#######  tabla de labels/agents en excel #########
#json_labels_all=labels.get_labels_all(token)   
#write_text.write_json_file(json_labels_all) 
#################################################
#
#######  tabla de labels/agents en excel #########

def test000():
    return "hola test"

def fetch_labels() -> List[str]:
    token=auth_get_token()
    return token

#json_labels_all=labels2.get_labels_all(token)   
#write_text.write_json_file(json_labels_all) 
#################################################

#
#json_labels=labels.get_labels_status(token)  
#write_text.write_json_file(json_labels) 
#
#json_labels=labels.get_labels_test(token)    

#json_labels=networklog.get_labels_status(token)  
#write_text.write_json_file(json_labels) 


#################################################
#incidents
#incs=incidents.get_incidents(token)   

#for inc in incs:
#    token=authenticate.auth_get_token()
#    incidents.get_incident_detail(token,inc)
#################################################
