#!/usr/bin/python3

from requests.auth import AuthBase
import json
import jwt
import re

try:
    import source.helpers.default_post_session
except:
    import default_post_session


class JWTSession(default_post_session.DefaultPostSession):
    """
    User session using a JWT token for authentication.
    """

    def __init__(self, host, login_path,
            user_field, pwd_field, valid_status_code=None,
            jwt_header="Authorization", jwt_method="Bearer", **kwargs
        ):
        super().__init__(host, login_path, user_field, pwd_field, valid_status_code, **kwargs) 
        self.jwt_header = jwt_header
        self.jwt_method = jwt_method


    def _check_jwt(self, token):
        """Check if given token is a JWT by trying to decode it"""
        try:
            algorithm = jwt.get_unverified_header(token).get('alg')
            jwt.decode(token=token, algorithms=algorithm, verify=False)
            return True
        except:
            return False


    def parse_login_response(self, response):
        """
        Parse response body to find the JWT. If some strings match, we try to decode it
        to check if it's a JWT. If the check is successful, the user is logged in and the
        authentication method is set for the session.
        """
        body = response.text
        # Search JWT with regex in the response body
        r = re.findall("[\w_-]{3,}\.[\w_-]{3,}\.[\w_-]*", body)
        # Try to decode for each matching strings to avoid false positive
        for possible_token in r:
            if self._check_jwt(possible_token):
                # A valid JWT is found
                self.session.auth = JWTAuth(possible_token)
                self.is_logged = True
                break


    class JWTAuth(AuthBase):
        """
        This class add necessary headers for JWT authentication. The headers can be passed
        as a parameter of the JWTSession class and by default is "Authorization: Bearer".
        """
        def __init__(self, token):
            """JWT is stored in object"""
            self.token = token
        
        def __call__(self, r):
            """Add authentication header before each future requests"""
            r.headers[self.jwt_header] = f"{self.jwt_method} {self.token}"
            return r

