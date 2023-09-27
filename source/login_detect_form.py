#!/usr/bin/python3

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.proxy import Proxy, ProxyType


class LoginFieldsDetector():
    
    DEF_USER = "username@gmail.com"
    DEF_PWD  = "ExamplePa$$word#123"

    def __init__(self, login_page: str, testing_creds=None, use_browser=False, **kwargs):
        # Login parameters
        self.login_page = login_page
        if isinstance(testing_creds, tuple) and len(testing_creds) == 2:
            self.username, self.password = testing_creds
        else:
            self.username, self.password = (self.DEF_USER, self.DEF_PWD)
        # Requests parameters
        self.parameters = kwargs
        self.parameters.update({
            "headers": {"User-Agent": "Mozilla/5.0"}
        })
        # Headless browser parameters
        self.use_browser = use_browser
        if self.use_browser:
            self.browser = self._create_browser(proxies=self.parameters.get('proxies'))
        else:
            self.session = requests.Session()
        # Result
        self.computed_payload = None

    
    def _create_browser(self, proxies=None):
        opt = webdriver.FirefoxOptions()
        opt.add_argument("--headless")
        # Add proxy configuration if needed
        if proxies:
            opt.proxy = Proxy({
                "proxyType": ProxyType.MANUAL,
                "httpProxy": proxies.get("http"),
                "sslProxy": proxies.get("https")
            })
        return webdriver.Firefox(options=opt)

 
    def _get_login_page(self) -> str:
        if self.use_browser:
            self.browser.get(self.login_page)
            return self.browser.page_source
        return self.session.get(self.login_page, allow_redirects=False, **self.parameters).text


    def _post_login_page(self, payload, json=False):
        if json:
            return self.session.post(self.login_page, json=payload, **self.parameters)
        return self.session.post(self.login_page, data=payload, **self.parameters)


    def _construct_payload(self, inputs: list) -> dict:
        """Construct a login payload (dictionnary) from a list of inputs"""
        payload = {}
        user_field, pwd_field = (None, None)
        for item in inputs:
            # If input type is password, add a password value (strong for password policies)
            if item.type == 'password':
                pwd_field = item.name
                payload[pwd_field] = self.password
            # Add submit input if required
            elif item.type == 'submit':
                if item.name and item.required:
                    payload[item.name] = item.value
            # Add hidden fields and with pre-filled values (if any)
            elif item.type == 'hidden' or item.value:
                payload[item.name] = item.value
            # It leaves username (probably)
            else:
                user_field = item.name
                payload[user_field] = self.username
        return self.ConfigurablePayload(payload, user_field, pwd_field)


    def _parse_response_fields(self, response: str) -> list:
        """Parse the login page to get all the inputs in forms"""
        parsed = BeautifulSoup(response, 'html.parser')
        # Find all forms in the page
        forms = parsed.find_all('form')
        payloads = list()
        for form in forms:
            # In each form, find all fields (input)
            raw_inputs = form.find_all('input')
            inputs = list()
            for raw_input in raw_inputs:
                inputs.append(self.Input(raw_input))
            # Construct the payload if there is a password field
            if any([i.type == "password" for i in inputs]):
                payloads.append(self._construct_payload(inputs))
        # Return differents constructed payload
        return payloads


    def _choose_payload(self, payloads: list) -> dict:
        # If there is only one possible payload, return it
        if len(payloads) == 1:
            return payloads[0]
        """
        # Else, try to find the correct payload
        result = list()
        for payload in payloads:
            resp = self._post_login_page(payload.body)
            # Bad request
            if resp.status_code != 400:
                result.append(payload)
        # To do, not satisfying method
        """
        return None if len(payloads) == 0 else result[0]



    def detect_fields(self) -> bool:
        """
        Detect the needed fields for authentication for the given login page.
        This function works in 3 steps:
          - Send a GET request to the login page,
          - Parse the response to find login fields,
          - Compute the payload from the parsed data.
        If a valid payload is found returns True, else returns False.
        """
        resp = self._get_login_page()
        payloads = self._parse_response_fields(resp)
        self.computed_payload = self._choose_payload(payloads)
        return self.computed_payload is not None


    def get_payload(self, username, password):
        """
        Returns the payload found with given parameters. If the payload wasn't
        detected before, try to detect it. Return None if no valid payload was
        found.
        """
        # Try if payload is already detected 
        if self.computed_payload is None:
            # If not, detect or redetect fields
            if not self.detect_fields():
                # Doesn't find any valid payload
                return None
        # A valid payload exists, return it with given parameters
        return self.computed_payload.set_params(username, password)


    class Input():
        """Helper class for input fields"""
        def __init__(self, input_tag):
            self.name = input_tag.get('name')
            self.type = input_tag.get('type')
            self.value = input_tag.get('value')
            self.required = bool(input_tag.get('required'))
            self.hidden = bool(input_tag.get('hidden'))

    
    class ConfigurablePayload():
        """Helper class for payload"""
        def __init__(self, body, user_field, pwd_field):
            self.body = body
            self.user_field = user_field
            self.pwd_field = pwd_field

        def set_params(self, username, password):
            payload = self.body.copy()
            payload[self.user_field] = username
            payload[self.pwd_field]  = password
            return payload



if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    url = "https://www.root-me.org/?page=login"
    
    username = "louka.bvn@gmail.com"
    password = input(f"Enter {url} password")

    lfd = LoginFieldsDetector(url, verify=False, proxies={"https": "127.0.0.1:8080"})
    lfd_browser = LoginFieldsDetector(url, use_browser=True, verify=False, proxies={"https": "127.0.0.1:8080"})

    for detector in [lfd, lfd_browser]:
        detector.detect_fields()
        payload = detector.get_payload(username, password)
        resp = detector._post_login_page(payload)
        # print(resp.text)


