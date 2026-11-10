# @name Authenticated chat socket
# @description The handshake needs a bearer token (captured by auth/login.curl in collection runs).
# @tags websocket
--expand-url {{WS_URL}}/ws/chat
--expand-header "Authorization: Bearer {{API_TOKEN}}"
