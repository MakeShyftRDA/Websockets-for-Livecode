script "websockets.livecodescript"
//*********************************************************************************
//Websockets RFC 6455 standard .https://datatracker.ietf.org/doc/html/rfc6455
//MIT License
//Compiled by Tom Glod (ww.makeshyft.com)
//Code written by Anthropic's Claude Opus
//Tested and Corrected by all contributors (Thank you to all)
//July 11, 2024
//https://github.com/MakeShyftRDA/Websockets-for-Livecode
//*********************************************************************************
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
   
   return tPort
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
   local tPorts
   
   // IF PPORTS IS EMPTY, STOP ALL SERVERS
   if pPorts is empty then
      put the keys of sWebSocketServers into tPorts
   else
      put pPorts into tPorts
   end if
   
   // OTHERWISE, STOP SERVERS ON SPECIFIED PORTS
   repeat for each line tPort in tPorts
      // CLOSE SOCKETS
      if sWebSocketServers[tPort]["protocol"] is "wss" then
         close socket (":" & tPort)
      else
         close socket tPort
      end if
      
      // REMOVE SERVER DATA FROM SWEBSOCKETSERVERS
      delete variable sWebSocketServers[tPort]
      
      // CLOSE ANY ACTIVE CONNECTIONS ON THIS PORT
      repeat for each key tSocketID in sWebSocketConnections
         if sWebSocketConnections[tSocketID]["port"] is tPort then
            __WebSocketCloseConnection tSocketID, 1001, "Server Shutting Down"
         end if
      end repeat
   end repeat
end websocketStop

on __WebSocketNewConnection pSocketID, pLocalPort
   local tPort
   
   // CREATE A NEW ENTRY IN SWEBSOCKETCONNECTIONS FOR THIS SOCKET
   put pLocalPort into sWebSocketConnections[pSocketID]["port"]
   put "connecting" into sWebSocketConnections[pSocketID]["status"]
   
   // READ THE HTTP UPGRADE REQUEST
   read from socket pSocketID until crlf & crlf with message "__WebSocketHandshake"
   
   if the result is not empty then
      // HANDLE READ ERROR
      delete variable sWebSocketConnections[pSocketID]
      close socket pSocketID
      exit __WebSocketNewConnection
   end if
   
   // CONTROL WILL BE PASSED TO __WEBSOCKETHANDSHAKE WHEN DATA IS READ
end __WebSocketNewConnection

private command __WebSocketHandshake pSocketID, pData
   local tHeaders, tKey, tAccept, tSubprotocol, tResponse
   
   // PARSE THE HTTP HEADERS FROM PDATA
   __ParseHeaders pData, tHeaders
   
   // VERIFY IT'S A VALID WEBSOCKET UPGRADE REQUEST
   if tHeaders["Upgrade"] is not "websocket" or \
      tHeaders["Connection"] contains not "Upgrade" or \
      tHeaders["Sec-WebSocket-Key"] is empty or \
      tHeaders["Sec-WebSocket-Version"] is not "13" then
      __WebSocketCloseConnection pSocketID, 400, "Invalid WebSocket upgrade request"
      exit __WebSocketHandshake
   end if
   
   // HANDLE SUBPROTOCOL NEGOTIATION
   put tHeaders["Sec-WebSocket-Protocol"] into tSubprotocol
   if tSubprotocol is not empty then
      // HERE YOU WOULD SELECT A SUPPORTED SUBPROTOCOL
      // FOR NOW, WE'LL JUST USE THE FIRST ONE OFFERED
      put item 1 of tSubprotocol into tSubprotocol
   end if
   
   // GENERATE THE SEC-WEBSOCKET-ACCEPT VALUE
   put tHeaders["Sec-WebSocket-Key"] into tKey
   put __WebSocketComputeAccept(tKey) into tAccept
   
   // SEND THE WEBSOCKET HANDSHAKE RESPONSE WITH SELECTED SUBPROTOCOL
   put "HTTP/1.1 101 Switching Protocols" & CR into tResponse
   put "Upgrade: websocket" & CR after tResponse
   put "Connection: Upgrade" & CR after tResponse
   put "Sec-WebSocket-Accept:" && tAccept & CR after tResponse
   if tSubprotocol is not empty then
      put "Sec-WebSocket-Protocol:" && tSubprotocol & CR after tResponse
   end if
   put CR after tResponse
   
   write tResponse to socket pSocketID
   
   // IF SUCCESSFUL, UPDATE CONNECTION STATUS AND START READING WEBSOCKET FRAMES
   if the result is empty then
      put "OPEN" into sWebSocketConnections[pSocketID]["status"]
      put tSubprotocol into sWebSocketConnections[pSocketID]["subprotocol"]
      read from socket pSocketID with message "__WebSocketReadData"
      
      // CALL __SETUPTIMEOUTS
      __SetupTimeouts pSocketID
   else
      __WebSocketCloseConnection pSocketID, 1002, "Handshake failed"
   end if
end __WebSocketHandshake


private command __ParseHeaders pHeaderData, @xHeaders
   // PARSES HTTP HEADERS FROM A STRING INTO AN ARRAY
   // PHEADERDATA: THE STRING CONTAINING THE HTTP HEADERS
   // @XHEADERS: THE ARRAY TO STORE THE PARSED HEADERS (PASSED BY REFERENCE)
   local tLastHeader, tIndex
   
   // SPLIT THE HEADER DATA INTO INDIVIDUAL LINES
   split pHeaderData by CR and LF
   
   set the itemDelimiter to ":"
   repeat with tIndex = 1 to the number of elements in pHeaderData
      if pHeaderData[tIndex] begins with space or \
            pHeaderData[tIndex] begins with tab then
         // CONTINUATION OF PREVIOUS HEADER
         put space & word 1 to -1 of pHeaderData[tIndex] after xHeaders[tLastHeader]
      else
         // NEW HEADER
         put item 1 of pHeaderData[tIndex] into tLastHeader
         if tLastHeader is empty then next repeat
         
         delete item 1 of pHeaderData[tIndex]
         put word 1 to -1 of pHeaderData[tIndex] into xHeaders[tLastHeader]
      end if
   end repeat
end __ParseHeaders

on __WebSocketReadData pSocketID, pData
   local tBuffer, tFrame, tFrameLength, tMessage, tFinalMessage, tOpcode, tFIN
   
   // APPEND PDATA TO THE CONNECTION'S BUFFER
   put pData after sWebSocketConnections[pSocketID]["buffer"]
   
   // WHILE THERE'S A COMPLETE FRAME IN THE BUFFER
   repeat while the length of sWebSocketConnections[pSocketID]["buffer"] > 0
      put __WebSocketParseFrame(sWebSocketConnections[pSocketID]["buffer"]) into tFrame
      if tFrame is empty then
         // NOT ENOUGH DATA FOR A COMPLETE FRAME
         exit repeat
      end if
      
      put tFrame["length"] into tFrameLength
      put tFrame["opcode"] into tOpcode
      put tFrame["FIN"] into tFIN
      put tFrame["payload"] into tMessage
      
      // HANDLE FRAGMENTED MESSAGES
      if tOpcode is 0 then
         // CONTINUATION FRAME
         put tMessage after sWebSocketConnections[pSocketID]["fragmentedMessage"]
         if tFIN is true then
            put sWebSocketConnections[pSocketID]["fragmentedMessage"] into tFinalMessage
            put empty into sWebSocketConnections[pSocketID]["fragmentedMessage"]
         end if
      else if tOpcode is among the items of "1,2" then
         if tFIN is false then
            // START OF A NEW FRAGMENTED MESSAGE
            put tMessage into sWebSocketConnections[pSocketID]["fragmentedMessage"]
            put tOpcode into sWebSocketConnections[pSocketID]["fragmentedOpcode"]
         else
            // SINGLE FRAME MESSAGE
            put tMessage into tFinalMessage
         end if
      else
         // CONTROL FRAMES (CLOSE, PING, PONG)
         put tMessage into tFinalMessage
      end if
      
      // PROCESS THE FRAME OR COMPLETE MESSAGE
      switch tOpcode
         case 1 // TEXT FRAME
         case 2 // BINARY FRAME
            if tFinalMessage is not empty then
               local tFinalOpcode
               put sWebSocketConnections[pSocketID]["fragmentedOpcode"] into tFinalOpcode
               if tFinalOpcode is empty then put tOpcode into tFinalOpcode
               dispatch sWebSocketServers[sWebSocketConnections[pSocketID]["port"]]["callback"] to sWebSocketServers[sWebSocketConnections[pSocketID]["port"]]["target"] with pSocketID, tFinalMessage, tFinalOpcode
               put empty into sWebSocketConnections[pSocketID]["fragmentedOpcode"]
            end if
            break
         case 8 // CLOSE FRAME
            __WebSocketHandleClose pSocketID, tFinalMessage
            break
         case 9 // PING FRAME
            __WebSocketHandlePing pSocketID, tFinalMessage
            break
         case 10 // PONG FRAME
            __WebSocketHandlePong pSocketID, tFinalMessage
            break
      end switch
      
      // REMOVE THE PROCESSED FRAME FROM THE BUFFER
      delete char 1 to tFrameLength of sWebSocketConnections[pSocketID]["buffer"]
   end repeat
end __WebSocketReadData

command websocketSend pSocketID, pMessage, pType
   local tFrame, tOpcode, tError
   
   // VALIDATE PTYPE (TEXT OR BINARY)
   switch pType
      case "text"
         put 1 into tOpcode
         break
      case "binary"
         put 2 into tOpcode
         break
      default
         put "Invalid message type. Must be 'text' or 'binary'." into tError
         return tError for error
   end switch
   
   // VALIDATE SOCKET CONNECTION
   if sWebSocketConnections[pSocketID]["status"] is not "OPEN" then
      put "WebSocket connection is not open." into tError
      return tError for error
   end if
   
   // CREATE A WEBSOCKET FRAME USING __WEBSOCKETCREATEFRAME
   put __WebSocketCreateFrame(pMessage, tOpcode, false) into tFrame
   if tFrame is empty then
      put "Failed to create WebSocket frame." into tError
      return tError for error
   end if
   
   // SEND THE FRAME OVER THE SOCKET
   write tFrame to socket pSocketID with message "__WebSocketFrameSent"
   put the result into tError
   
   if tError is not empty then
      return "Failed to send WebSocket frame: " & tError for error
   end if
end websocketSend

on __WebSocketFrameSent pSocketID
   // THIS HANDLER IS CALLED AFTER A FRAME HAS BEEN SENT
   // UPDATE THE LAST ACTIVITY TIMESTAMP
   put the milliseconds into sWebSocketConnections[pSocketID]["lastActivity"]
   
   // CHECK IF THE CONNECTION IS STILL OPEN
   if sWebSocketConnections[pSocketID]["status"] is not "OPEN" then
      // THE CONNECTION WAS CLOSED DURING SEND, HANDLE ACCORDINGLY
      __WebSocketCloseConnection pSocketID, 1006, "Connection closed unexpectedly"
   end if
end __WebSocketFrameSent

command websocketClose pSocketID, pStatusCode, pReason
   local tCloseFrame, tResponse, tTimeoutTime, tError
   
   // VALIDATE INPUTS AND CONNECTION STATUS
   if pSocketID is empty or sWebSocketConnections[pSocketID] is empty then
      return "Invalid socket ID" for error
   end if
   if sWebSocketConnections[pSocketID]["status"] is "CLOSED" then
      return "Connection already closed" for error
   end if
   
   // SET DEFAULT VALUES IF NOT PROVIDED
   if pStatusCode is empty then put 1000 into pStatusCode
   if pReason is empty then put "Normal Closure" into pReason
   
   // CREATE A CLOSE FRAME WITH STATUS CODE AND REASON
   put __WebSocketCreateFrame(numToChar(pStatusCode div 256) & numToChar(pStatusCode mod 256) & pReason, 8, true) into tCloseFrame
   
   // SEND THE CLOSE FRAME
   write tCloseFrame to socket pSocketID
   put the result into tError
   if tError is not empty then
      return "Failed to send close frame:" && tError for error
   end if
   
   // UPDATE CONNECTION STATUS
   put "CLOSING" into sWebSocketConnections[pSocketID]["status"]
   
   // SET TIMEOUT FOR WAITING CLOSE FRAME RESPONSE
   put the milliseconds + 5000 into tTimeoutTime
   
   // WAIT FOR CLOSE FRAME RESPONSE OR TIMEOUT
   repeat until the milliseconds > tTimeoutTime
      if sWebSocketConnections[pSocketID]["status"] is "CLOSED" then
         exit repeat
      end if
      wait 50 milliseconds with messages
   end repeat
   
   // FORCE CLOSE IF NO RESPONSE RECEIVED
   if sWebSocketConnections[pSocketID]["status"] is not "CLOSED" then
      put "CLOSED" into sWebSocketConnections[pSocketID]["status"]
   end if
   
   // CLOSE THE SOCKET
   close socket pSocketID
   put the result into tError
   if tError is not empty then
      return "Failed to close socket:" && tError for error
   end if
   
   // NOTIFY THE APPLICATION OF THE CLOSED CONNECTION
   local tPort
   put sWebSocketConnections[pSocketID]["port"] into tPort
   dispatch sWebSocketServers[tPort]["callback"] to sWebSocketServers[tPort]["target"] with pSocketID, "CLOSED", pStatusCode, pReason
   
   // REMOVE CONNECTION DATA FROM SWEBSOCKETCONNECTIONS
   delete variable sWebSocketConnections[pSocketID]
   
   return empty
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
