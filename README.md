# auto-detect-login - in progress

This tool wants to provide an auto detection of login method and a way to make authentication automatic for the majority of web applications.

For the login request, the tool parses the login page to find the correct fields and values to send to the server, and for the response, there is differents login methods classes that will parse the response and create a session in which the needed parameters will be added in each future request.

The goal is to provide a way to authenticate in each web applications without having to write specific scripts for it, and so this tool is aimed to be reused in other projects and scripts.
