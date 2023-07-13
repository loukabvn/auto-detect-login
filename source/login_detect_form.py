#!/usr/bin/python3

import requests
from bs4 import BeautifulSoup

class LoginFieldsDetector():

    def __init__(self, login_page: str):
        self.login_page = login_page

    def get_login_fields(self):
        resp = requests.get(self.login_page)
        fields = self.auto_detect_fields(resp)
        return fields

    def login_try(self, inputs: list):
        payload = {}
        for input_field in inputs:
            # Add hidden or pre-filled fields
            if input_field['value'] != '' or input_field['type'] == 'hidden':
                payload[input_field['name']] = input_field['value']
            # If input type is password, add a password value (strong for password policies)
            if input_field['type'] == 'password':
                payload[input_field['name']] = 'ExamplePa$$word#123'
            # Add submit input if required
            if input_field['type'] == 'submit'
                if input_field['name'] and input_field['required']:
                    payload[input_field['name']] = input_field['value']
            # It leaves username (probably)
            else:
                user_field = input_field['name']
                payload[user_field] = 'username@gmail.com' if "mail" in user_field else "username"
        print(payload)

    def auto_detect_fields(self, response: requests.Response) -> list:
        parsed = BeautifulSoup(response.text, 'html.parser')
        forms = parsed.find_all('form')
        for form in forms:
            raw_inputs = form.find_all('input')
            inputs = []
            for i in raw_inputs:
                inputs.append({
                    "name"    : i.get('name'),
                    "type"    : i.get('type'),
                    "value"   : i.get('value'),
                    "hidden"  : True if i.get('hidden') else False,
                    "required": True if i.get('required') else False
                })
            # print(inputs)
            self.login_try(inputs)


if __name__ == "__main__":
    lfd = LoginFieldsDetector("https://www.root-me.org/?page=login")
    lfd.get_login_fields()
