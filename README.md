[comment]: # "Auto-generated SOAR connector documentation"
# WebForm URL Prompt

Publisher: FDSE  
Connector Version: 1\.0\.3  
Product Vendor: Splunk  
Product Name: WebForm URL Prompt 
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.0  

This application allows alternative to native SOAR prompts, an interactive web-based form to capture prompt-like responses.

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Windows Server asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**placeholder\_url** |  optional  | string | Placeholder URL (end-user Display URL)
**url\_prompt\_handler** |  required  | string | URL Prompt Handler

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[check response](#action-check-response) - Check for the Response for given Unique URL  
[generate url prompt](#action-generate-url-prompt) - Generate URL Prompt  

## action: 'test connectivity'
Validate the asset configuration for connectivity supplied configuration\.

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'check response'
Check for the Response for given Unique URL

Type: **generic**  
Read only: **False**

This actions makes an API call at given interval to check whether any response is received. When the response is received by end-user via form, action adds the response into data paths. Such input from form could be used by filter/decision blocks as an input for the downstream workflow in playbook\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**interval** |  optional  | Retry interval | numeric |  
**response\_url** |  required  | Input generated unique url to check response | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.response\_url | string | 
action\_result\.parameter.interval | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   


## action: 'generate url prompt'
Generate URL Prompt

Type: **generic**  
Read only: **False**

This action accepts dynamic input to generate dynamic web-form, and returns URL which can be sent over Email, Slack, or any other methods to capture user input\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**banner** |  required  | Title banner for the form generated | string |  
**message** |  required  | Question or a message for the end-user | string | 
**options** |  required  | Comma-separated list of options to be presented to end-user | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.banner| string | 
action\_result\.parameter\.message| string | 
action\_result\.parameter\.options| string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   