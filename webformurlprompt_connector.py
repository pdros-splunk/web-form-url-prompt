#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from webformurlprompt_consts import *
import requests
import json
from bs4 import BeautifulSoup
import time

class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class WebformUrlPromptConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(WebformUrlPromptConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # make rest call
        response = requests.get("http://10.202.36.157:81/")

        if "root" not in response.text:
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress(f"Test Connectivity Failed. - {response.text}")
            # return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_generate_url_prompt(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Action Params
        banner = param.get('banner', 'SOAR Web Prompt')
        message =  param.get('message', "Default - Do you concur? ")
        options = param.get('options', "Default, Yes, No")

        # Global Asset Config
        config = self.get_config()
        placeholder_domain = config.get('placeholder_url', 'http://10.202.36.157:81/')
        url = config.get('url_prompt_handler', "http://10.202.36.157:81/")
        self.save_progress("[-] Generating URL for Prompt via {}".format(url))
        
        payload = {}
        payload['data'] = { "mode": "Generate url",
                            "message": message,
                            "options": options,
                            "response_url": "NA",
                            "email": "NA",
                            "banner": banner}
        
        
        url = "{}/prompt?action=from_phantom".format(url)
        result = self.__generate_url(url, payload, action_result)

        self.save_progress("result: {}".format(str(result)))
        if result == False:
            return action_result.set_status(
                phantom.APP_ERROR,
                'Unable to get url for prompt - ' + str(response.text)
            )
        # action_result.update_summary(summary)
        try:
            pid = result.get('url').split("pid=")[1]
            result['placeholder'] = "{}/prompt?pid={}".format(placeholder_domain, pid)
            self.save_progress("\n\n\n----- Placeholder URL -----\n\n\n\n[-] Prompt Link: {}\n\n\n\n".format(result['placeholder']))
        except Exception as e:
            self.save_progress("Something's Phishy: {}".fromat(e))
        
        action_result.add_data(result)
        
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_check_response(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        response_url = param['response_url']

        # Optional values should use the .get() function
        interval = param.get('interval', 30)

        tries = 2880
        message = ""
        # Check if response_url is None
        url = "{}&get_response=yes".format(response_url)
        self.save_progress("[-] We shall get response at {}".format(url))
        self.save_progress("[-] Waiting for response")
        if response_url is not None:
            try:
                while tries != 0:
                    tries = tries - 1
                    self.send_progress(".")
                    result = self.__wait_for_response(url, action_result)
                    # self.save_progress("result: {}".format(result))
                    if result.get('user_response', 'No') == "yes":
                        result['data']['message'] = result['data']['comment']
                        result['data']['url'] = url
                        break
                    else:
                        time.sleep(interval)

            except Exception as e:
                self.save_progress("Error while waiting for response: {}".format(e))

            selection_list = result.get('data').get('selection_list')
            summary = {
                    'message': "Number of options selected {}".format(selection_list),
                    'count': "{}".format(len(selection_list))
                }
            action_result.update_summary(summary)
            action_result.add_data(result.get('data'))

        self.save_progress(".")
        return action_result.set_status(
                phantom.APP_SUCCESS,
                'Successfully performed "Wait for Response".'
            )

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'generate_url_prompt':
            ret_val = self._handle_generate_url_prompt(param)

        if action_id == 'check_response':
            ret_val = self._handle_check_response(param)

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def __generate_url(self, url, payload, action_result):
        # Generate URL
        result = {}
        try:
            # payload = {'prompt': 'value1', 'header': 'value2'}
            # headers = {'x-request-from': 'phantom-prompt'}
            # resp = requests.post(url, data=payload, headers=headers)
            headers = {'Content-Type': 'application/json'}
            resp = requests.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                self.send_progress("[-] Status Code: {}".format(resp.status_code))
                self.send_progress("[-] Error Code: {}".format(resp.text))
                return action_result.set_status(
                phantom.APP_ERROR,
                'Unable to get url for prompt - ' + str(response.texts)
                )
            # self.save_progress("[-] Result - {}".format(resp.text))
            result = resp.json()

        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                'Unable to get url for prompt - ' + err.message
        )

        return result

    def __wait_for_response(self, url, action_result):
        # Check if User replied
        # self.save_progress("[-] In __wait_for_response")
        result = {}
        try:
            # payload = {'prompt': 'value1', 'header': 'value2'}
            # headers = {'x-request-from': 'phantom-prompt'}
            headers = {'Content-Type': 'application/json'}
            resp = requests.get(url, headers=headers)
            if resp.status_code != 200:
                self.send_progress("[-] Status Code: {}".format(resp.status_code))
                return action_result.set_status(
                phantom.APP_ERROR,
                'Unable to get url for prompt - ' + str(response.texts)
                )
            result = resp.json()

        except Exception as err:
            self.save_progress("Error: {}".format(err))
            return action_result.set_status(
                phantom.APP_ERROR,
                'Unable to get url for prompt - ' + err.message
        )

        return result
    
    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = WebformUrlPromptConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = WebformUrlPromptConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
