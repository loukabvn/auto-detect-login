#!/usr/bin/python3

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.auth import AuthBase
from bs4 import BeautifulSoup


class AbstractUserSession:
    """
    Abstract user session class. This class defines the methods that can be used with any user session
    and also defines the common code and methods that needs to be implemented for any login method. A
    new login method class can be implemented as a child of AbstractUserSession by implementing the
    send_login_request and parse_login_response methods and a custom requests.auth.AuthBase child
    class if necessary.
    """

    HTTP  = "http://"
    HTTPS = "https://"

    DEFAULT_VALID_STATUS_CODE = 200
    
    def __init__(self, host: str, login_path: str, https=True, json_body=False, **kwargs):
        """
        Initialize a AbstractUserSession object. Set the host and the path to the application login
        page (login_path). By default it will use HTTPS but you can disable it by setting https
        argument to False. Also by default it will send body in POST request with data parameters
        but you can send by default JSON by setting json parameter to True.
        Any additional arguments accepted in requests.request() method can be pass to this function
        and will be send in all future HTTP request.
        """
        # Requests parameters
        self.host = host
        self.protocol = self.HTTPS if https else self.HTTP
        self.json_body = json_body
        # Login parameters
        self.login_path = login_path
        self.session = requests.Session()
        self.is_logged = False
        # Dictionary with requests parameters
        self.parameters = kwargs
        # Test if a proxy is set and update parameters and session
        self._update_proxy()


    def _update_proxy(self):
        """
        If a proxy is set in the parameters, set the parameters "verify" to False and disable
        requests.InsecureRequestWarning to avoid errors.
        """
        try:
            proxies = self.parameters['proxies']
            if proxies is not None:
                self.session.verify = False
                self.session.proxies.update(proxies)
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        except KeyError:
            pass


    def _url(self, path: str) -> str:
        """
        Returns the constructed URL with the parameter path based on the host and protocol set before.
        """
        return self.protocol + self.host + ('' if path.startswith('/') else '/') + path


    def _parse_login_fields(self, response: requests.Response) -> list:
        parsed = BeautifulSoup(r.text, 'html.parser')
        forms = parsed.find_all('form')
        for form in forms:
           inputs = form.find_all('input') 


    def get(self, path: str, **kwargs) -> requests.Response:
        """
        Wrapper for requests.Session().get() using the parameters of the instance. You can pass to this
        function any optional parameters accepted by the requests.Session().get() function. Returns a
        requests.Response object.
        """
        kwargs.update(self.parameters)
        return self.session.get(self._url(path), **kwargs)


    def post(self, path: str, payload: dict, **kwargs) -> requests.Response:
        """
        Wrapper for requests.Session().post() using the parameters of the instance. You can pass to this
        function any optional parameters accepted by the requests.Session().post() function. The payload
        data must be a dictionnary, and may be send as URL-encoded form or JSON depending of the boolean
        json parameter (by default json=False). Returns a requests.Response object.
        """
        kwargs.update(self.parameters)
        if self.json_body:
            return self.session.post(self._url(path), json=payload, **kwargs)
        else:
            return self.session.post(self._url(path), data=payload, **kwargs)

    
    def login(self, user: str, pwd: str, **kwargs) -> bool:
        """
        Login method. It starts by sending the login request and then parse the HTTP response to detect
        if login suceed or not. Then register a hook if login method require to send a specific header
        or anything in future HTTP requests. Returns the value of self.is_logged.
        """    
        response = self.send_login_request(user, pwd, **kwargs)
        self.parse_login_response(response)
        return self.is_logged


    def set_login_method(self, login_method: requests.auth.AuthBase):
        """
        Set the login method for the user session. The parameter login_method must implements the
        requests.auth.AuthBase class.
        """
        if login_method and hasattr(login_method, "mro") and requests.auth.AuthBase in login_method.mro():
            self.session.auth = login_method

    def detect_login_fields(self):
        resp = self.get(self.login_path)
        fields = self._parse_login_fields(resp)
        return fields

    def reset_session(self):
        """Reset user session. The proxy and login method are saved and set again after the reset"""
        login_method = self.session.auth
        self.session.close()
        self.session = requests.Session()
        self.session.auth = login_method
        self._update_proxy()

    """
    The following functions defines the way the login method works. They must be implemented in child
    classes when creating a new login method.
    """

    def send_login_request(self, user: str, pwd: str, **kwargs) -> requests.Response:
        """Defines the way of how the login request is send. Returns the login request response."""
        raise NotImplementedError("This method must be implemented in child classes")


    def parse_login_response(self, response: requests.Response):
        """
        Parse the login request response to detect if login succeed.
        On success, self.is_logged must be set to True. Also, if the application authentication method
        doesn't rely on cookies, the attribute self.session.auth must be set with any requests.AuthBase
        class implementation.
        """
        raise NotImplementedError("This method must be implemented in child classes")

