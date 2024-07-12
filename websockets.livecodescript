local sWebSocketServers
local sWebSocketConnections

command websocketStart pCallback, pPort, pServerName
   // VALIDATE INPUT PARAMETERS
   // SET UP DEFAULT VALUES IF NOT PROVIDED
   // ACCEPT CONNECTIONS ON THE SPECIFIED PORT
   // STORE SERVER INFORMATION IN SWEBSOCKETSERVERS ARRAY
   // RETURN THE PORT NUMBER OR AN ERROR
end websocketStart

command websocketSecureStart pCallback, pPort, pServerName, pCertificateFile, pKeyFile
   // SIMILAR TO WEBSOCKETSTART, BUT SET UP TLS
   // USE SSLACCEPT INSTEAD OF ACCEPT FOR THE CONNECTION
end websocketSecureStart

command websocketStop pPorts
   // IF PPORTS IS EMPTY, STOP ALL SERVERS
   // OTHERWISE, STOP SERVERS ON SPECIFIED PORTS
   // CLOSE SOCKETS AND REMOVE SERVER DATA FROM SWEBSOCKETSERVERS
end websocketStop

on __WebSocketNewConnection pSocketID, pLocalPort
   // CREATE A NEW ENTRY IN SWEBSOCKETCONNECTIONS FOR THIS SOCKET
   // READ THE HTTP UPGRADE REQUEST
   // PASS CONTROL TO __WEBSOCKETHANDSHAKE
end __WebSocketNewConnection

private command __WebSocketHandshake pSocketID, pData
   // PARSE THE HTTP HEADERS FROM PDATA
   // VERIFY IT'S A VALID WEBSOCKET UPGRADE REQUEST
   // HANDLE SUBPROTOCOL NEGOTIATION
   // GENERATE THE SEC-WEBSOCKET-ACCEPT VALUE
   // SEND THE WEBSOCKET HANDSHAKE RESPONSE WITH SELECTED SUBPROTOCOL
   // IF SUCCESSFUL, UPDATE CONNECTION STATUS AND START READING WEBSOCKET FRAMES
   // CALL __SETUPTIMEOUTS
end __WebSocketHandshake

on __WebSocketReadData pSocketID, pData
   // APPEND PDATA TO THE CONNECTION'S BUFFER
   // WHILE THERE'S A COMPLETE FRAME IN THE BUFFER:
   //   PARSE THE FRAME USING __WEBSOCKETPARSEFRAME
   //   IF FRAGMENTED MESSAGE:
   //     ACCUMULATE FRAGMENTS UNTIL FINAL FRAME IS RECEIVED
   //   PROCESS THE FRAME OR COMPLETE MESSAGE (HANDLE CONTROL FRAMES, DISPATCH MESSAGE FRAMES)
   //   REMOVE THE PROCESSED FRAME FROM THE BUFFER
end __WebSocketReadData

command websocketSend pSocketID, pMessage, pType
   // VALIDATE PTYPE (TEXT OR BINARY)
   // CREATE A WEBSOCKET FRAME USING __WEBSOCKETCREATEFRAME
   // SEND THE FRAME OVER THE SOCKET
end websocketSend

command websocketClose pSocketID, pStatusCode, pReason
   // CREATE A CLOSE FRAME WITH STATUS CODE AND REASON
   // SEND THE CLOSE FRAME
   // WAIT FOR CLOSE FRAME RESPONSE OR TIMEOUT
   // CLOSE THE SOCKET
end websocketClose

command websocketPing pSocketID, pData
   // CREATE A PING FRAME WITH OPTIONAL DATA
   // SEND THE PING FRAME
   // SET UP A TIMER TO WAIT FOR PONG RESPONSE
end websocketPing

on __WebSocketHandlePong pSocketID, pData
   // PROCESS THE RECEIVED PONG FRAME
   // CLEAR THE PING TIMER
   // UPDATE CONNECTION STATUS IF NECESSARY
end __WebSocketHandlePong

private command __WebSocketCloseConnection pSocketID, pStatusCode, pReason
   // SEND CLOSE FRAME IF NOT ALREADY SENT
   // CLOSE THE SOCKET
   // REMOVE CONNECTION DATA FROM SWEBSOCKETCONNECTIONS
   // NOTIFY THE APPLICATION OF THE CLOSED CONNECTION
end __WebSocketCloseConnection

private function __WebSocketParseFrame pData
   // IMPLEMENT FRAME PARSING ACCORDING TO RFC 6455 SECTION 5.2
   // RETURN AN ARRAY WITH FRAME INFORMATION (FIN, OPCODE, MASK, PAYLOAD, ETC.)
end __WebSocketParseFrame

private function __WebSocketCreateFrame pPayload, pOpcode, pMask
   // IMPLEMENT FRAME CREATION ACCORDING TO RFC 6455 SECTION 5.2
   // RETURN THE BINARY FRAME DATA
end __WebSocketCreateFrame

private function __WebSocketMaskUnmaskData pData, pMaskingKey
   // XOR THE DATA WITH THE MASKING KEY AS PER RFC 6455 SECTION 5.3
   // RETURN THE MASKED/UNMASKED DATA
end __WebSocketMaskUnmaskData

private function __WebSocketGenerateKey
   // GENERATE A RANDOM 16-BYTE VALUE
   // ENCODE IT IN BASE64
   // RETURN THE ENCODED KEY
end __WebSocketGenerateKey

private function __WebSocketComputeAccept pKey
   // CONCATENATE PKEY WITH THE WEBSOCKET GUID
   // COMPUTE THE SHA-1 HASH
   // ENCODE THE HASH IN BASE64
   // RETURN THE COMPUTED ACCEPT VALUE
end __WebSocketComputeAccept

private function __Base64Encode pData
   // IMPLEMENT BASE64 ENCODING
end __Base64Encode

private function __Base64Decode pData
   // IMPLEMENT BASE64 DECODING
end __Base64Decode

private function __Sha1 pData
   // IMPLEMENT SHA-1 HASHING
end __Sha1

on __WebSocketDataReceived pSocketID, pMessage, pType
   // DISPATCH THE RECEIVED MESSAGE TO THE APPLICATION
end __WebSocketDataReceived

on __WebSocketConnectionClosed pSocketID, pStatusCode, pReason
   // NOTIFY THE APPLICATION OF THE CLOSED CONNECTION
end __WebSocketConnectionClosed

private command __SetupTimeouts pSocketID
   // SET READ TIMEOUT
   // SET WRITE TIMEOUT
   // SET PING INTERVAL
end __SetupTimeouts

on __WebSocketTimeout pSocketID, pTimeoutType
   // HANDLE VARIOUS TIMEOUT SCENARIOS (READ, WRITE, PING)
end __WebSocketTimeout