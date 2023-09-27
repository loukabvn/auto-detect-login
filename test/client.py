#!/usr/bin/python3

import sys
import importlib
from time import sleep

### Load classes

# Login helpers classes
AVAILABLE_SESSIONS = [
    'basic_auth_session',
    'cookie_session',
    'jwt_session',
    'digest_auth_session',
    'proxy_auth_session'
]

session_classes = dict()

sys.path.append("../")
for cls in AVAILABLE_SESSIONS:
    session_classes.update({
        cls: importlib.import_module(f"source.methods.{cls}")
    })

### Test server parameters

HOST = "127.0.0.1:5000"
ENDPOINTS = [
    {"login": '/csrf_auth/login',       "restricted": '/csrf_auth/protected'    },
    {"login": '/default_auth/login',    "restricted": '/default_auth/protected' },
    {"login": '/jwt_auth/login',        "restricted": '/jwt_auth/protected'     },
    {"login": '/basic_auth/protected',  "restricted": '/basic_auth/protected'   },
    {"login": '/digest_auth/protected', "restricted": '/digest_auth/protected'  },
    {"login": '/proxy_auth/protected',  "restricted": '/proxy_auth/protected'   }
]

### Proxy parameters

BURP_PROXY = {
    "http" : "127.0.0.1:8080",
    "https": "127.0.0.1:8080"
}

### Test all methods with each endpoints

def main():
    # Valid creds
    username, password = "root", "toor"
    # For each endpoints, try each methods
    for endpoint in ENDPOINTS:
        for cls in session_classes.values():
            print(f"Test: {endpoint['login']} with {cls.Session.name} class")
            # Create a session
            session = cls.Session(
                HOST, endpoint['login'] + f"?class={cls.Session.name}",
                https=False, proxies=BURP_PROXY
            )
            # Try to login
            session.login(username, password)
            # Test if login succeed
            if session.is_logged(endpoint['restricted']):
                print("Successfully logged in ! - {:<22} - {:<22}".format(
                    endpoint['login'], cls.Session.name
                ))
            print()
    print("Done")

if __name__ == "__main__":
    main()

