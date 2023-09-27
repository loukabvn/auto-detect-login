#!/usr/bin/python3

from source.usersession import AbstractUserSession

class Session(AbstractUserSession):
    """
    Detect a valid login upon a given status code in response. Authentication token
    is stored in cookies, so there is no need to define a custom auth class.
    """
    name = "CookieSession"

    def __init__(self, host, login_path, valid_status_codes: list | tuple=None, **kwargs):
        super().__init__(host, login_path, **kwargs)
        self.valid_status_codes = valid_status_codes or self.DEFAULT_VALID_STATUS_CODES

    def parse_login_response(self, response):
        if response.status_code in self.valid_status_codes:
            self.auth_success = True
