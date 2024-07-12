script "websockets.livecodescript"
local sWebSocketServers
local sWebSocketConnections

constant kDefaultPort = 8080
constant kDefaultServerName = "LiveCode WebSocket Server"

command websocketStart pCallback, pPort, pServerName
   local tPort, tServerName, tError
   
   // VALIDATE INPUT PARAMETERS
   if pCallback is empty then
      return "Callback cannot be empty" for error
   end if
   
   // SET UP DEFAULT VALUES IF NOT PROVIDED
   if pPort is empty then
      put kDefaultPort into tPort
   else
      put pPort into tPort
   end if
   
   if pServerName is empty then
      put kDefaultServerName into tServerName
   else
      put pServerName into tServerName
   end if
   
   // ACCEPT CONNECTIONS ON THE SPECIFIED PORT
   accept connections on port tPort with message "__WebSocketNewConnection"
   put the result into tError
   if tError is not empty then
      if tPort is kDefaultPort then
         // TRY WITH AN EPHEMERAL PORT
         accept connections on port "0" with message "__WebSocketNewConnection"
         put the result into tError
         if tError is not empty then
            return tError for error
         end if
         put it into tPort
      else
         return tError for error
      end if
   end if
   
   // STORE SERVER INFORMATION IN SWEBSOCKETSERVERS ARRAY
   put __GetCaller() into sWebSocketServers[tPort]["target"]
   put pCallback into sWebSocketServers[tPort]["callback"]
   put tServerName into sWebSocketServers[tPort]["servername"]
   put "ws" into sWebSocketServers[tPort]["protocol"]
   
   return tPort for value
end websocketStart

command websocketSecureStart pCallback, pPort, pServerName, pCertificateFile, pKeyFile
   local tPort, tServerName, tError
   
   // VALIDATE INPUT PARAMETERS
   if pCallback is empty then
      return "Callback cannot be empty" for error
   end if
   if pCertificateFile is empty or pKeyFile is empty then
      return "Certificate and key files must be specified" for error
   end if
   if there is not a file pCertificateFile then
      return "Certificate file not found" for error
   end if
   if there is not a file pKeyFile then
      return "Key file not found" for error
   end if
   
   // SET UP DEFAULT VALUES IF NOT PROVIDED
   if pPort is empty then
      put kDefaultPort into tPort
   else
      put pPort into tPort
   end if
   
   if pServerName is empty then
      put kDefaultServerName into tServerName
   else
      put pServerName into tServerName
   end if
   
   // SET UP TLS
   set the sslCertificates to pCertificateFile & "," & pKeyFile
   
   // ACCEPT SECURE CONNECTIONS ON THE SPECIFIED PORT
   set the socketTimeoutInterval to 0
   open secure socket (":" & tPort) with message "__WebSocketNewConnection"
   put the result into tError
   if tError is not empty then
      if tPort is kDefaultPort then
         // TRY WITH AN EPHEMERAL PORT
         open secure socket ":0" with message "__WebSocketNewConnection"
         put the result into tError
         if tError is not empty then
            return tError for error
         end if
         put the last word of the openSockets into tPort
      else
         return tError for error
      end if
   end if
   
   // STORE SERVER INFORMATION IN SWEBSOCKETSERVERS ARRAY
   put __GetCaller() into sWebSocketServers[tPort]["target"]
   put pCallback into sWebSocketServers[tPort]["callback"]
   put tServerName into sWebSocketServers[tPort]["servername"]
   put "wss" into sWebSocketServers[tPort]["protocol"]
   put pCertificateFile into sWebSocketServers[tPort]["certificateFile"]
   put pKeyFile into sWebSocketServers[tPort]["keyFile"]
   
   return tPort for value
end websocketSecureStart

private function __GetCaller
   get item 1 to -3 of line -3 of the executionContexts
   if there is not an it then
      delete item -1 of it
   end if
   return it
end __GetCaller

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
