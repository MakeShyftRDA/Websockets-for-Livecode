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

constant kWebSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
constant kDefaultPort = 8080
constant kDefaultServerName = "LiveCode WebSocket Server"

// *******************************************************************************
// SERVER SIDE
// *******************************************************************************
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
   local tPingFrame, tError, tTimeoutTime
   
   // VALIDATE SOCKET CONNECTION
   if pSocketID is empty or sWebSocketConnections[pSocketID] is empty then
      put "Invalid socket ID" into tError
      return tError for error
   end if
   if sWebSocketConnections[pSocketID]["status"] is not "OPEN" then
      put "WebSocket connection is not open" into tError
      return tError for error
   end if
   
   // CREATE A PING FRAME WITH OPTIONAL DATA
   put __WebSocketCreateFrame(pData, 9, false) into tPingFrame
   if tPingFrame is empty then
      put "Failed to create WebSocket ping frame" into tError
      return tError for error
   end if
   
   // SEND THE PING FRAME
   write tPingFrame to socket pSocketID with message "__WebSocketPingSent"
   put the result into tError
   if tError is not empty then
      return "Failed to send WebSocket ping frame:" && tError for error
   end if
   
   // SET UP A TIMER TO WAIT FOR PONG RESPONSE
   put the milliseconds + 30000 into tTimeoutTime // 30 SECONDS TIMEOUT
   put tTimeoutTime into sWebSocketConnections[pSocketID]["pingTimeout"]
   
   // START THE TIMER
   send "__WebSocketPingTimeout" to me in 30000 milliseconds with pSocketID
   
   // STORE THE PING DATA FOR VERIFICATION
   put pData into sWebSocketConnections[pSocketID]["lastPingData"]
   put the milliseconds into sWebSocketConnections[pSocketID]["lastPingTime"]
   
   return empty
end websocketPing

on __WebSocketPingSent pSocketID
   // UPDATE THE LAST ACTIVITY TIMESTAMP
   put the milliseconds into sWebSocketConnections[pSocketID]["lastActivity"]
end __WebSocketPingSent

on __WebSocketPingTimeout pSocketID
   if sWebSocketConnections[pSocketID] is not empty and \
         sWebSocketConnections[pSocketID]["pingTimeout"] is not empty and \
         the milliseconds > sWebSocketConnections[pSocketID]["pingTimeout"] then
      // PING TIMEOUT OCCURRED
      __WebSocketCloseConnection pSocketID, 1002, "Ping timeout"
   end if
end __WebSocketPingTimeout

on __WebSocketHandlePong pSocketID, pData
   local tPort, tCallback, tTarget, tError
   
   // CHECK IF THE CONNECTION EXISTS
   if sWebSocketConnections[pSocketID] is empty then
      put "Invalid socket ID or connection closed" into tError
      exit __WebSocketHandlePong
   end if
   
   // GET THE PORT AND CALLBACK INFORMATION
   put sWebSocketConnections[pSocketID]["port"] into tPort
   if sWebSocketServers[tPort] is empty then
      put "Server information not found" into tError
      exit __WebSocketHandlePong
   end if
   put sWebSocketServers[tPort]["callback"] into tCallback
   put sWebSocketServers[tPort]["target"] into tTarget
   
   // CLEAR THE PING TIMER
   if sWebSocketConnections[pSocketID]["pingTimer"] is not empty then
      cancel sWebSocketConnections[pSocketID]["pingTimer"]
      put empty into sWebSocketConnections[pSocketID]["pingTimer"]
   end if
   
   // UPDATE LAST ACTIVITY TIMESTAMP
   put the milliseconds into sWebSocketConnections[pSocketID]["lastActivity"]
   
   // UPDATE CONNECTION STATUS
   put "OPEN" into sWebSocketConnections[pSocketID]["status"]
   
   // NOTIFY THE APPLICATION OF THE PONG
   try
      dispatch tCallback to tTarget with pSocketID, "PONG", pData
   catch tError
      // LOG THE ERROR BUT CONTINUE PROCESSING
      put "Error dispatching PONG callback:" && tError after msg
   end try
   
   // SCHEDULE THE NEXT PING
   send "__WebSocketSendPing" to me in 30000 milliseconds with pSocketID
   put the result into sWebSocketConnections[pSocketID]["pingTimer"]
   
   // LOG ANY ERRORS
   if tError is not empty then
      put "WebSocket Pong Handler Error:" && tError after msg
   end if
end __WebSocketHandlePong

private command __WebSocketCloseConnection pSocketID, pStatusCode, pReason
   local tCloseFrame, tError, tPort
   
   // VALIDATE INPUTS
   if pSocketID is empty or sWebSocketConnections[pSocketID] is empty then
      exit __WebSocketCloseConnection
   end if
   
   // SEND CLOSE FRAME IF NOT ALREADY SENT
   if sWebSocketConnections[pSocketID]["status"] is not among the items of "CLOSING,CLOSED" then
      // ENSURE STATUS CODE IS VALID
      if pStatusCode is empty then 
         put 1000 into pStatusCode
      end if
      if pReason is empty then
         put "Normal Closure" into pReason
      end if
      
      put __WebSocketCreateFrame(numToChar(pStatusCode div 256) & numToChar(pStatusCode mod 256) & pReason, 8, true) into tCloseFrame
      write tCloseFrame to socket pSocketID
      put the result into tError
      if tError is empty then
         put "CLOSING" into sWebSocketConnections[pSocketID]["status"]
      else
         // LOG ERROR IF UNABLE TO SEND CLOSE FRAME
         put "Error sending close frame:" && tError into msg
      end if
   end if
   
   // CLOSE THE SOCKET
   if the socket of pSocketID is not empty then
      close socket pSocketID
      put the result into tError
      if tError is not empty then
         // LOG ERROR IF UNABLE TO CLOSE SOCKET
         put "Error closing socket:" && tError into msg
      end if
   end if
   
   // REMOVE CONNECTION DATA FROM SWEBSOCKETCONNECTIONS
   put sWebSocketConnections[pSocketID]["port"] into tPort
   delete variable sWebSocketConnections[pSocketID]
   
   // NOTIFY THE APPLICATION OF THE CLOSED CONNECTION
   if there is a sWebSocketServers[tPort]["target"] and there is a sWebSocketServers[tPort]["callback"] then
      try
         dispatch sWebSocketServers[tPort]["callback"] to sWebSocketServers[tPort]["target"] with pSocketID, "CLOSED", pStatusCode, pReason
      catch tError
         put "Error dispatching close notification:" && tError into msg
      end try
   end if
end __WebSocketCloseConnection

private function __WebSocketParseFrame pData
   local tFrame, tByte1, tByte2, tMaskingKey, tPayloadLength, tPayload
   local tHeaderLength, i
   
   // ENSURE WE HAVE AT LEAST 2 BYTES FOR THE FRAME HEADER
   if the length of pData < 2 then
      return empty
   end if
   
   // PARSE THE FIRST TWO BYTES
   put charToNum(char 1 of pData) into tByte1
   put charToNum(char 2 of pData) into tByte2
   
   // EXTRACT FRAME INFORMATION FROM THE FIRST BYTE
   put (tByte1 bitAnd 128) is 128 into tFrame["FIN"]
   put (tByte1 bitAnd 64) is 64 into tFrame["RSV1"]
   put (tByte1 bitAnd 32) is 32 into tFrame["RSV2"]
   put (tByte1 bitAnd 16) is 16 into tFrame["RSV3"]
   put tByte1 bitAnd 15 into tFrame["opcode"]
   
   // EXTRACT MASK AND PAYLOAD LENGTH FROM THE SECOND BYTE
   put (tByte2 bitAnd 128) is 128 into tFrame["mask"]
   put tByte2 bitAnd 127 into tPayloadLength
   
   // DETERMINE THE ACTUAL PAYLOAD LENGTH AND HEADER LENGTH
   put 2 into tHeaderLength
   if tPayloadLength is 126 then
      if the length of pData < 4 then return empty
      put binaryDecode("H", char 3 to 4 of pData, "tPayloadLength") into tPayloadLength
      add 2 to tHeaderLength
   else if tPayloadLength is 127 then
      if the length of pData < 10 then return empty
      put binaryDecode("Q", char 3 to 10 of pData, "tPayloadLength") into tPayloadLength
      add 8 to tHeaderLength
   end if
   
   // EXTRACT MASKING KEY IF PRESENT
   if tFrame["mask"] then
      add 4 to tHeaderLength
      if the length of pData < tHeaderLength then return empty
      put char (tHeaderLength - 3) to tHeaderLength of pData into tMaskingKey
   end if
   
   put tHeaderLength into tFrame["headerLength"]
   
   // ENSURE WE HAVE THE ENTIRE FRAME
   if the length of pData < (tHeaderLength + tPayloadLength) then
      return empty
   end if
   
   // EXTRACT THE PAYLOAD
   put char (tHeaderLength + 1) to (tHeaderLength + tPayloadLength) of pData into tPayload
   
   // UNMASK THE PAYLOAD IF NECESSARY
   if tFrame["mask"] then
      put __WebSocketMaskUnmaskData(tPayload, tMaskingKey) into tFrame["payload"]
   else
      put tPayload into tFrame["payload"]
   end if
   
   // SET THE TOTAL FRAME LENGTH
   put tHeaderLength + tPayloadLength into tFrame["length"]
   
   // ADD PAYLOAD LENGTH TO THE FRAME INFO
   put tPayloadLength into tFrame["payloadLength"]
   
   return tFrame
end __WebSocketParseFrame

private function __WebSocketCreateFrame pPayload, pOpcode, pMask
   local tFrame, tPayloadLength, tMaskingKey, tMaskedPayload, tError
   
   // VALIDATE INPUTS
   if pPayload is empty then put empty into pPayload
   if pOpcode is not among the items of "0,1,2,8,9,10" then
      put "Invalid opcode" into tError
      return tError for error
   end if
   
   // CREATE THE FIRST BYTE OF THE FRAME
   put numToByte(binaryEncode("b", "1") & binaryEncode("b", "000") & binaryEncode("b", baseConvert(pOpcode, 10, 2))) into tFrame // SET FIN BIT AND OPCODE
   
   // DETERMINE PAYLOAD LENGTH AND ADD LENGTH BYTES
   put length(pPayload) into tPayloadLength
   if tPayloadLength < 126 then
      put numToByte(tPayloadLength) after tFrame
   else if tPayloadLength < 65536 then
      put numToByte(126) after tFrame
      put binaryEncode("n", tPayloadLength) after tFrame
   else
      put numToByte(127) after tFrame
      put binaryEncode("N", tPayloadLength) after tFrame
   end if
   
   // ADD MASKING KEY IF REQUIRED
   if pMask then
      put binaryEncode("b", "1") after byte 2 of tFrame // SET MASK BIT
      put __WebSocketGenerateKey() into tMaskingKey
      if tMaskingKey is empty then
         put "Failed to generate masking key" into tError
         return tError for error
      end if
      put tMaskingKey after tFrame
      put __WebSocketMaskUnmaskData(pPayload, tMaskingKey) into tMaskedPayload
   else
      put pPayload into tMaskedPayload
   end if
   
   // ADD PAYLOAD DATA
   put tMaskedPayload after tFrame
   
   return tFrame
end __WebSocketCreateFrame

private function __WebSocketMaskUnmaskData pData, pMaskingKey
   local tMaskedData, tDataLength, tKeyLength, tKeyIndex, tChar, tKeyChar
   
   // INITIALIZE VARIABLES
   put empty into tMaskedData
   put the length of pData into tDataLength
   put the length of pMaskingKey into tKeyLength
   
   // ENSURE THE MASKING KEY IS 4 BYTES
   if tKeyLength is not 4 then
      return "Error: Invalid masking key length" for error
   end if
   
   // PROCESS EACH BYTE OF THE DATA
   repeat with i = 1 to tDataLength
      put (i - 1) mod 4 + 1 into tKeyIndex
      put charToNum(char i of pData) into tChar
      put charToNum(char tKeyIndex of pMaskingKey) into tKeyChar
      
      // PERFORM XOR OPERATION AND APPEND TO RESULT
      put numToChar(tChar bitXor tKeyChar) after tMaskedData
   end repeat
   
   return tMaskedData
end __WebSocketMaskUnmaskData

private function __WebSocketComputeAccept pKey
   local tConcatenatedKey, tSha1Hash, tBase64EncodedHash
   
   // CONCATENATE PKEY WITH THE WEBSOCKET GUID
   put pKey & kWebSocketGUID into tConcatenatedKey
   
   // COMPUTE THE SHA-1 HASH
   put __Sha1(tConcatenatedKey) into tSha1Hash
   
   // ENCODE THE HASH IN BASE64
   put __Base64Encode(tSha1Hash) into tBase64EncodedHash
   
   // RETURN THE COMPUTED ACCEPT VALUE
   return tBase64EncodedHash
end __WebSocketComputeAccept

private function __WebSocketGenerateKey
   local tRandomBytes, tEncodedKey
   
   // GENERATE A RANDOM 16-BYTE VALUE
   put urandom(16) into tRandomBytes
   
   // ENCODE IT IN BASE64
   put base64Encode(tRandomBytes) into tEncodedKey
   
   // RETURN THE ENCODED KEY
   return tEncodedKey
end __WebSocketGenerateKey

private function __Base64Encode pData
   local tEncodedData
   
   // USE LIVECODE'S BUILT-IN BASE64ENCODE FUNCTION
   put base64Encode(pData) into tEncodedData
   
   return tEncodedData
end __Base64Encode

private function __Base64Decode pData
   local tDecodedData
   
   // USE LIVECODE'S BUILT-IN BASE64DECODE FUNCTION
   put base64Decode(pData) into tDecodedData
   
   return tDecodedData
end __Base64Decode

private function __Sha1 pData
   local tHashedData
   
   // USE LIVECODE'S BUILT-IN SHA1DIGEST FUNCTION
   put sha1Digest(pData) into tHashedData
   
   return tHashedData
end __Sha1

on __WebSocketDataReceived pSocketID, pMessage, pType
   local tPort, tCallback, tTarget, tError
   
   // VALIDATE INPUT PARAMETERS
   if pSocketID is empty then
      put "Invalid socket ID" into tError
      return tError for error
   end if
   
   // CHECK IF THE CONNECTION EXISTS
   if sWebSocketConnections[pSocketID] is empty then
      put "WebSocket connection not found for socket" && pSocketID into tError
      return tError for error
   end if
   
   // GET THE PORT FOR THIS CONNECTION
   put sWebSocketConnections[pSocketID]["port"] into tPort
   
   // ENSURE THE SERVER INFO EXISTS
   if sWebSocketServers[tPort] is empty then
      put "Server information not found for port" && tPort into tError
      return tError for error
   end if
   
   // GET THE CALLBACK AND TARGET FOR THIS SERVER
   put sWebSocketServers[tPort]["callback"] into tCallback
   put sWebSocketServers[tPort]["target"] into tTarget
   
   // ENSURE THE CALLBACK AND TARGET ARE VALID
   if tCallback is empty or tTarget is empty then
      put "Invalid callback or target for port" && tPort into tError
      return tError for error
   end if
   
   // DISPATCH THE MESSAGE TO THE APPLICATION
   try
      dispatch tCallback to tTarget with pSocketID, pMessage, pType
   catch tError
      // LOG THE ERROR BUT CONTINUE PROCESSING
      put "Error dispatching WebSocket data:" && tError & return after msg
   end try
   
   // UPDATE THE LAST ACTIVITY TIMESTAMP
   put the milliseconds into sWebSocketConnections[pSocketID]["lastActivity"]
   
   // RESET THE READ TIMEOUT
   __SetupTimeouts pSocketID
end __WebSocketDataReceived

on __WebSocketConnectionClosed pSocketID, pStatusCode, pReason
   local tPort, tCallback, tTarget, tError
   
   // GET THE PORT ASSOCIATED WITH THIS CONNECTION
   put sWebSocketConnections[pSocketID]["port"] into tPort
   
   // CHECK IF THE SERVER INFO EXISTS FOR THIS PORT
   if sWebSocketServers[tPort] is empty then
      put "Server information not found for port" && tPort into tError
      put tError after msg
      exit __WebSocketConnectionClosed
   end if
   
   // GET THE CALLBACK AND TARGET FROM THE SERVER INFO
   put sWebSocketServers[tPort]["callback"] into tCallback
   put sWebSocketServers[tPort]["target"] into tTarget
   
   // NOTIFY THE APPLICATION OF THE CLOSED CONNECTION
   try
      dispatch tCallback to tTarget with pSocketID, "CLOSED", pStatusCode, pReason
   catch tError
      put "Error notifying application of closed connection:" && tError after msg
   end try
   
   // REMOVE THE CONNECTION DATA FROM SWEBSOCKETCONNECTIONS
   delete variable sWebSocketConnections[pSocketID]
end __WebSocketConnectionClosed

private command __SetupTimeouts pSocketID
   local tPingInterval
   
   // SET GLOBAL SOCKET TIMEOUT
   set the socketTimeoutInterval to 30000 // 30 SECONDS FOR ALL SOCKET OPERATIONS
   
   // SET PING INTERVAL
   put 60000 into tPingInterval // 60 SECONDS
   
   // STORE PING INTERVAL IN THE CONNECTION DATA
   put tPingInterval into sWebSocketConnections[pSocketID]["pingInterval"]
   
   // SCHEDULE NEXT PING
   send "__WebSocketSendPing" to me in tPingInterval milliseconds with pSocketID
   put the result into sWebSocketConnections[pSocketID]["pingTimer"]
   
   // STORE LAST ACTIVITY TIMESTAMP
   put the milliseconds into sWebSocketConnections[pSocketID]["lastActivity"]
end __SetupTimeouts

on __WebSocketTimeout pSocketID, pTimeoutType
   local tStatusCode, tReason
   
   // HANDLE VARIOUS TIMEOUT SCENARIOS
   switch pTimeoutType
      case "socket"
         put 1002 into tStatusCode
         put "Socket timeout" into tReason
         break
      case "ping"
         put 1002 into tStatusCode
         put "Ping timeout" into tReason
         break
      default
         put 1002 into tStatusCode
         put "Unknown timeout" into tReason
   end switch
   
   // CLOSE THE CONNECTION
   __WebSocketCloseConnection pSocketID, tStatusCode, tReason
   
   // LOG THE TIMEOUT
   put "WebSocket timeout:" && pTimeoutType && "for socket" && pSocketID after msg
end __WebSocketTimeout


//**************************************************************************************************************************************
// TEST CODE
//**************************************************************************************************************************************

local sSocketID
local sTestPort

on testWebSocket
   local tError, tTestServiceURL
   
   // START THE WEBSOCKET SERVER
   websocketStart "handleWebSocketMessage", 0, "Test WebSocket Server"
   put the result into sTestPort
   if sTestPort is empty then
      put "Error starting WebSocket server:" && it into tError
      logError tError
      exit testWebSocket
   end if
   
   // CONNECT TO A WEBSOCKET TEST SERVICE (E.G., ECHO.WEBSOCKET.ORG)
   put "wss://echo.websocket.org" into tTestServiceURL
   
   // ATTEMPT TO CONNECT TO THE TEST SERVICE
   websocketConnect tTestServiceURL
   put it into sSocketID
   if sSocketID is empty then
      put "Error connecting to test service:" && the result into tError
      logError tError
      cleanupTest
      exit testWebSocket
   end if
   
   // SEND A TEST MESSAGE
   websocketSend sSocketID, "Hello, WebSocket!", "text"
   if the result is not empty then
      put "Error sending message:" && the result into tError
      logError tError
      cleanupTest
      exit testWebSocket
   end if
   
   // WAIT FOR RESPONSE (WITH TIMEOUT)
   send "handleResponseTimeout" to me in 5000 milliseconds
   wait until sWebSocketConnections[sSocketID]["lastReceivedMessage"] is not empty with messages
   cancel "handleResponseTimeout"
   
   if sWebSocketConnections[sSocketID]["lastReceivedMessage"] is empty then
      put "Timeout waiting for response" into tError
      logError tError
      cleanupTest
      exit testWebSocket
   end if
   
   // VERIFY THE RECEIVED MESSAGE
   if sWebSocketConnections[sSocketID]["lastReceivedMessage"] is not "Hello, WebSocket!" then
      put "Unexpected response:" && sWebSocketConnections[sSocketID]["lastReceivedMessage"] into tError
      logError tError
      cleanupTest
      exit testWebSocket
   end if
   
   // TEST SUCCESSFUL
   logTheMessage "WebSocket test completed successfully!"
   
   cleanupTest
end testWebSocket

on handleWebSocketMessage pSocketID, pMessage, pType
   // HANDLE INCOMING WEBSOCKET MESSAGES
   switch pType
      case 1 // TEXT MESSAGE
         put "Received text message:" && pMessage
         put pMessage into sWebSocketConnections[pSocketID]["lastReceivedMessage"]
         break
      case 2 // BINARY MESSAGE
         put "Received binary message, length:" && the length of pMessage
         put pMessage into sWebSocketConnections[pSocketID]["lastReceivedMessage"]
         break
      case "OPEN"
         put "WebSocket connection opened"
         break
      case "CLOSE"
         put "WebSocket connection closed"
         break
      case "ERROR"
         put "WebSocket error:" && pMessage
         logError pMessage
         break
   end switch
end handleWebSocketMessage

on handleResponseTimeout
   put "Response timeout occurred" into sWebSocketConnections[sSocketID]["lastReceivedMessage"]
end handleResponseTimeout

on cleanupTest
   // CLOSE THE CONNECTION
   if sSocketID is not empty then
      websocketClose sSocketID
   end if
   
   // STOP THE WEBSOCKET SERVER
   if sTestPort is not empty then
      websocketStop sTestPort
   end if
   
   // CLEAR VARIABLES
   put empty into sSocketID
   put empty into sTestPort
end cleanupTest

command logTheMessage pMessage
   put pMessage & return after msg
   if there is a field "Log" then
      put pMessage & return after field "Log"
   end if
end logTheMessage

command logError pError
   put "ERROR:" && pError & return after msg
   if there is a field "Log" then
      put "ERROR:" && pError & return after field "Log"
   end if
end logError


// *******************************************************************************
// CLIENT SIDE
// *******************************************************************************



command websocketConnect pURL
   local tError, tProtocol, tHost, tPort, tPath, tSecure,tURLParts
   local tSocketID, tKey, tHandshake, tResponse
   
   // VALIDATE THE URL
   if pURL is empty then
      put "Invalid WebSocket URL" into tError
      return tError for error
   end if
   
   // PARSE THE URL TO EXTRACT HOST, PORT, PATH, AND PROTOCOL (WS OR WSS)
   put urlParse(pURL) into tURLParts
   put tURLParts["scheme"] into tProtocol
   put tURLParts["host"] into tHost
   put tURLParts["port"] into tPort
   put tURLParts["path"] into tPath
   
   if tProtocol is not among the items of "ws,wss" then
      put "Invalid WebSocket protocol" into tError
      return tError for error
   end if
   
   put (tProtocol is "wss") into tSecure
   
   if tPort is empty then
      if tSecure then
         put "443" into tPort
      else
         put "80" into tPort
      end if
   end if
   
   if tPath is empty then
      put "/" into tPath
   end if
   
   // CREATE A SOCKET CONNECTION (SECURE IF WSS)
   if tSecure then
      open secure socket to tHost & ":" & tPort with message "__WebSocketConnected"
   else
      open socket to tHost & ":" & tPort with message "__WebSocketConnected"
   end if
   put the result into tError
   if tError is not empty then
      return "Failed to open socket:" && tError for error
   end if
   put it into tSocketID
   
   // GENERATE WEBSOCKET KEY
   put __WebSocketGenerateKey() into tKey
   
   // SEND HTTP UPGRADE REQUEST
   put "GET" && tPath && "HTTP/1.1" & CR after tHandshake
   put "Host:" && tHost & ":" & tPort & CR after tHandshake
   put "Upgrade: websocket" & CR after tHandshake
   put "Connection: Upgrade" & CR after tHandshake
   put "Sec-WebSocket-Key:" && tKey & CR after tHandshake
   put "Sec-WebSocket-Version: 13" & CR after tHandshake
   put CR after tHandshake
   
   write tHandshake to socket tSocketID
   
   // PROCESS SERVER RESPONSE
   read from socket tSocketID until empty with message "__WebSocketHandshakeResponse"
   
   // STORE CONNECTION INFORMATION
   put "CONNECTING" into sWebSocketConnections[tSocketID]["status"]
   put tHost into sWebSocketConnections[tSocketID]["host"]
   put tPort into sWebSocketConnections[tSocketID]["port"]
   put tPath into sWebSocketConnections[tSocketID]["path"]
   put tSecure into sWebSocketConnections[tSocketID]["secure"]
   put tKey into sWebSocketConnections[tSocketID]["key"]
   
   return tSocketID
end websocketConnect

on __WebSocketConnected pSocketID
   // CALLBACK FOR WHEN THE SOCKET CONNECTION IS ESTABLISHED
   if sWebSocketConnections[pSocketID] is empty then
      // HANDLE UNEXPECTED CONNECTION
      close socket pSocketID
      exit __WebSocketConnected
   end if
   
   // LOG CONNECTION
   put "WebSocket connection established for socket" && pSocketID after msg
end __WebSocketConnected

on __WebSocketHandshakeResponse pSocketID, pData
   local tResponse, tError
   
   put pData into tResponse
   
   // VERIFY WEBSOCKET HANDSHAKE
   if __WebSocketVerifyHandshake(tResponse, sWebSocketConnections[pSocketID]["key"]) is false then
      put "Invalid server handshake response" into tError
      __WebSocketHandleError pSocketID, tError
      exit __WebSocketHandshakeResponse
   end if
   
   // SET CONNECTION STATE TO OPEN
   put "OPEN" into sWebSocketConnections[pSocketID]["status"]
   
   // TRIGGER websocketHandleOpen CALLBACK
   dispatch "websocketHandleOpen" to me with pSocketID
   
   // START LISTENING FOR INCOMING MESSAGES
   read from socket pSocketID with message "__WebSocketReceive"
end __WebSocketHandshakeResponse

private function __WebSocketGenerateKey
   local tRandomBytes, tEncodedKey
   put urandom(16) into tRandomBytes
   put base64Encode(tRandomBytes) into tEncodedKey
   return tEncodedKey
end __WebSocketGenerateKey

private function __WebSocketVerifyHandshake pResponse, pKey
   local tLines, tAccept, tExpectedAccept
   
   set the itemDelimiter to ":"
   split pResponse by CR and LF
   
   if item 1 of line 1 of pResponse is not "HTTP/1.1 101" then return false
   if pResponse["Upgrade"] is not "websocket" then return false
   if pResponse["Connection"] contains not "Upgrade" then return false
   
   put pResponse["Sec-WebSocket-Accept"] into tAccept
   put __WebSocketComputeAccept(pKey) into tExpectedAccept
   
   return (tAccept is tExpectedAccept)
end __WebSocketVerifyHandshake

private function __WebSocketComputeAccept pKey
   local tConcatenatedKey, tSha1Hash, tBase64EncodedHash
   put pKey & kWebSocketGUID into tConcatenatedKey
   put sha1Digest(tConcatenatedKey) into tSha1Hash
   put base64Encode(tSha1Hash) into tBase64EncodedHash
   return tBase64EncodedHash
end __WebSocketComputeAccept

command __WebSocketHandleError pSocketID, pError
   // CLOSE THE SOCKET
   close socket pSocketID
   
   // REMOVE CONNECTION DATA
   delete variable sWebSocketConnections[pSocketID]
   
   // TRIGGER ERROR CALLBACK
   dispatch "websocketHandleError" to me with pSocketID, pError
end __WebSocketHandleError

command websocketDisconnect pSocketID
   local tError, tCloseFrame, tTimeoutTime
   
   // CHECK IF THE CONNECTION IS OPEN
   if sWebSocketConnections[pSocketID]["status"] is not "OPEN" then
      put "WebSocket connection is not open" into tError
      return tError for error
   end if
   
   // SEND A WEBSOCKET CLOSE FRAME
   put __WebSocketCreateFrame(numToChar(1000 div 256) & numToChar(1000 mod 256) & "Normal Closure", 8, true) into tCloseFrame
   write tCloseFrame to socket pSocketID
   if the result is not empty then
      put "Error sending close frame:" && the result into tError
      return tError for error
   end if
   
   // SET CONNECTION STATE TO CLOSING
   put "CLOSING" into sWebSocketConnections[pSocketID]["status"]
   
   // WAIT FOR CLOSE FRAME RESPONSE OR TIMEOUT
   put the milliseconds + 5000 into tTimeoutTime
   repeat until the milliseconds > tTimeoutTime
      if sWebSocketConnections[pSocketID]["status"] is "CLOSED" then
         exit repeat
      end if
      wait 50 milliseconds with messages
   end repeat
   
   // CLOSE THE SOCKET
   close socket pSocketID
   if the result is not empty then
      put "Error closing socket:" && the result into tError
      return tError for error
   end if
   
   // SET CONNECTION STATE TO CLOSED IF NOT ALREADY
   if sWebSocketConnections[pSocketID]["status"] is not "CLOSED" then
      put "CLOSED" into sWebSocketConnections[pSocketID]["status"]
   end if
   
   // TRIGGER websocketHandleClose CALLBACK
   dispatch "websocketHandleClose" to me with pSocketID, 1000, "Normal Closure"
   
   // REMOVE CONNECTION DATA
   delete variable sWebSocketConnections[pSocketID]
   
   return empty
end websocketDisconnect

command websocketSend pSocketID, pMessage, pType
   local tError, tOpcode, tFrame
   
   // VALIDATE THE SOCKET ID AND MESSAGE
   if pSocketID is empty or sWebSocketConnections[pSocketID] is empty then
      put "Invalid socket ID" into tError
      return tError for error
   end if
   
   if sWebSocketConnections[pSocketID]["status"] is not "OPEN" then
      put "WebSocket connection is not open" into tError
      return tError for error
   end if
   
   if pMessage is empty then
      put "Message cannot be empty" into tError
      return tError for error
   end if
   
   // DETERMINE THE OPCODE BASED ON PTYPE (TEXT OR BINARY)
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
   
   // CREATE A WEBSOCKET FRAME
   put __WebSocketCreateFrame(pMessage, tOpcode, true) into tFrame
   if tFrame is empty then
      put "Failed to create WebSocket frame" into tError
      return tError for error
   end if
   
   // SEND THE FRAME OVER THE SOCKET
   write tFrame to socket pSocketID
   put the result into tError
   if tError is not empty then
      return "Failed to send WebSocket frame:" && tError for error
   end if
   
   // UPDATE LAST ACTIVITY TIMESTAMP
   put the milliseconds into sWebSocketConnections[pSocketID]["lastActivity"]
   
   return empty
end websocketSend

function websocketIsConnected pSocketID
   local tIsConnected, tSocketStatus
   
   // INITIALIZE THE RETURN VALUE TO FALSE
   put false into tIsConnected
   
   // CHECK IF THE SOCKET ID IS VALID
   if pSocketID is not empty then
      // CHECK IF THE SOCKET EXISTS IN OUR CONNECTIONS ARRAY
      if sWebSocketConnections[pSocketID] is not empty then
         // GET THE CURRENT STATUS OF THE SOCKET
         put sWebSocketConnections[pSocketID]["status"] into tSocketStatus
         
         // CHECK IF THE SOCKET STATUS IS "OPEN"
         if tSocketStatus is "OPEN" then
            // VERIFY THE SOCKET IS ACTUALLY OPEN
            if the socket of pSocketID is not empty then
               put true into tIsConnected
            end if
         end if
      end if
   end if
   
   // RETURN TRUE IF CONNECTED, FALSE OTHERWISE
   return tIsConnected
end websocketIsConnected

on websocketHandleOpen pSocketID
   local tPort, tCallback, tTarget, tError
   
   // VALIDATE THE SOCKET ID
   if pSocketID is empty or sWebSocketConnections[pSocketID] is empty then
      put "Invalid socket ID or connection not found" into tError
      logError tError
      exit websocketHandleOpen
   end if
   
   // GET THE PORT FOR THIS CONNECTION
   put sWebSocketConnections[pSocketID]["port"] into tPort
   
   // ENSURE THE SERVER INFO EXISTS
   if sWebSocketServers[tPort] is empty then
      put "Server information not found for port" && tPort into tError
      logError tError
      exit websocketHandleOpen
   end if
   
   // GET THE CALLBACK AND TARGET FOR THIS SERVER
   put sWebSocketServers[tPort]["callback"] into tCallback
   put sWebSocketServers[tPort]["target"] into tTarget
   
   // ENSURE THE CALLBACK AND TARGET ARE VALID
   if tCallback is empty or tTarget is empty then
      put "Invalid callback or target for port" && tPort into tError
      logError tError
      exit websocketHandleOpen
   end if
   
   // DISPATCH THE OPEN EVENT TO THE APPLICATION
   try
      dispatch tCallback to tTarget with pSocketID, "OPEN"
   catch tError
      // LOG THE ERROR BUT CONTINUE PROCESSING
      logError "Error dispatching WebSocket open event:" && tError
   end try
   
   // UPDATE THE LAST ACTIVITY TIMESTAMP
   put the milliseconds into sWebSocketConnections[pSocketID]["lastActivity"]
   
   // SET UP TIMEOUTS FOR THIS CONNECTION
   __SetupTimeouts pSocketID
   
   // LOG SUCCESSFUL CONNECTION
   logTheMessage "WebSocket connection opened for socket" && pSocketID
end websocketHandleOpen

on websocketHandleMessage pSocketID, pMessage, pType
   local tLogMessage
   
   // VALIDATE INPUT PARAMETERS
   if pSocketID is empty then
      put "Error: Invalid socket ID" into tLogMessage
      logError tLogMessage
      exit websocketHandleMessage
   end if
   
   // LOG THE RECEIVED MESSAGE
   put "WebSocket message received on socket" && pSocketID into tLogMessage
   
   // HANDLE DIFFERENT MESSAGE TYPES
   switch pType
      case 1
         put " - Text message:" && pMessage after tLogMessage
         // HANDLE TEXT MESSAGE
         // ADD YOUR CUSTOM LOGIC HERE FOR TEXT MESSAGES
         break
      case 2
         put " - Binary message, length:" && the length of pMessage after tLogMessage
         // HANDLE BINARY MESSAGE
         // ADD YOUR CUSTOM LOGIC HERE FOR BINARY MESSAGES
         break
      default
         put " - Unknown message type:" && pType after tLogMessage
         // HANDLE UNKNOWN TYPE
         // ADD YOUR CUSTOM LOGIC HERE FOR UNKNOWN MESSAGE TYPES
   end switch
   
   // LOG THE MESSAGE DETAILS
   logTheMessage tLogMessage
   
   // UPDATE LAST ACTIVITY TIMESTAMP FOR THE CONNECTION
   if sWebSocketConnections[pSocketID] is not empty then
      put the milliseconds into sWebSocketConnections[pSocketID]["lastActivity"]
   end if
   
   // OPTIONAL: TRIGGER ANY CUSTOM APPLICATION LOGIC
   // YOU CAN ADD YOUR OWN CODE HERE TO HANDLE THE MESSAGE
   // BASED ON YOUR APPLICATION'S NEEDS
end websocketHandleMessage

on websocketHandleError pSocketID, pError
   local tPort, tCallback, tTarget, tLogMessage
   
   // VALIDATE INPUT PARAMETERS
   if pSocketID is empty then
      put "Error: Invalid socket ID" into tLogMessage
      logError tLogMessage
      exit websocketHandleError
   end if
   
   // LOG THE ERROR
   put "WebSocket error on socket" && pSocketID & ":" && pError into tLogMessage
   logError tLogMessage
   
   // GET THE PORT FOR THIS CONNECTION
   put sWebSocketConnections[pSocketID]["port"] into tPort
   
   // ENSURE THE SERVER INFO EXISTS
   if sWebSocketServers[tPort] is empty then
      put "Server information not found for port" && tPort into tLogMessage
      logError tLogMessage
      exit websocketHandleError
   end if
   
   // GET THE CALLBACK AND TARGET FOR THIS SERVER
   put sWebSocketServers[tPort]["callback"] into tCallback
   put sWebSocketServers[tPort]["target"] into tTarget
   
   // ENSURE THE CALLBACK AND TARGET ARE VALID
   if tCallback is empty or tTarget is empty then
      put "Invalid callback or target for port" && tPort into tLogMessage
      logError tLogMessage
      exit websocketHandleError
   end if
   
   // DISPATCH THE ERROR EVENT TO THE APPLICATION
   try
      dispatch tCallback to tTarget with pSocketID, "ERROR", pError
   catch tError
      put "Error dispatching WebSocket error event:" && tError into tLogMessage
      logError tLogMessage
   end try
   
   // CLOSE THE CONNECTION IF IT'S STILL OPEN
   if sWebSocketConnections[pSocketID] is not empty then
      if sWebSocketConnections[pSocketID]["status"] is "OPEN" then
         websocketClose pSocketID, 1006, "Abnormal Closure"
      end if
   end if
   
   // REMOVE THE CONNECTION DATA
   delete variable sWebSocketConnections[pSocketID]
end websocketHandleError

on websocketHandleClose pSocketID, pStatusCode, pReason
   local tPort, tCallback, tTarget, tLogMessage, tError
   
   // VALIDATE INPUT PARAMETERS
   if pSocketID is empty then
      put "Error: Invalid socket ID" into tLogMessage
      logError tLogMessage
      exit websocketHandleClose
   end if
   
   // LOG THE CLOSURE
   put "WebSocket connection closed on socket" && pSocketID && "with status code" && pStatusCode && "(" & pReason & ")" into tLogMessage
   logTheMessage tLogMessage
   
   // GET THE PORT FOR THIS CONNECTION
   if sWebSocketConnections[pSocketID] is not empty then
      put sWebSocketConnections[pSocketID]["port"] into tPort
   else
      put "Connection data not found for socket" && pSocketID into tLogMessage
      logError tLogMessage
      exit websocketHandleClose
   end if
   
   // ENSURE THE SERVER INFO EXISTS
   if sWebSocketServers[tPort] is empty then
      put "Server information not found for port" && tPort into tLogMessage
      logError tLogMessage
      exit websocketHandleClose
   end if
   
   // GET THE CALLBACK AND TARGET FOR THIS SERVER
   put sWebSocketServers[tPort]["callback"] into tCallback
   put sWebSocketServers[tPort]["target"] into tTarget
   
   // ENSURE THE CALLBACK AND TARGET ARE VALID
   if tCallback is empty or tTarget is empty then
      put "Invalid callback or target for port" && tPort into tLogMessage
      logError tLogMessage
      exit websocketHandleClose
   end if
   
   // DISPATCH THE CLOSE EVENT TO THE APPLICATION
   try
      dispatch tCallback to tTarget with pSocketID, "CLOSED", pStatusCode, pReason
   catch tError
      put "Error dispatching WebSocket close event:" && tError into tLogMessage
      logError tLogMessage
   end try
   
   // CLEAN UP THE CONNECTION DATA
   delete variable sWebSocketConnections[pSocketID]
   
   // ENSURE THE SOCKET IS CLOSED
   if the socket of pSocketID is not empty then
      close socket pSocketID
      if the result is not empty then
         put "Error closing socket" && pSocketID & ":" && the result into tLogMessage
         logError tLogMessage
      end if
   end if
end websocketHandleClose

private command __WebSocketReceive pSocketID, pData
   local tBuffer, tFrame, tOpcode, tPayload, tFIN, tError
   local tMasked, tMaskingKey, tUnmaskedPayload
   
   // BUFFER INCOMING DATA
   put pData after sWebSocketConnections[pSocketID]["buffer"]
   
   // PARSE COMPLETE WEBSOCKET FRAMES FROM THE BUFFER
   repeat while the length of sWebSocketConnections[pSocketID]["buffer"] > 0
      put __WebSocketParseFrame(sWebSocketConnections[pSocketID]["buffer"]) into tFrame
      if tFrame is empty then
         // NOT ENOUGH DATA FOR A COMPLETE FRAME
         exit repeat
      end if
      
      // EXTRACT FRAME INFORMATION
      put tFrame["opcode"] into tOpcode
      put tFrame["payload"] into tPayload
      put tFrame["FIN"] into tFIN
      put tFrame["mask"] into tMasked
      put tFrame["maskingKey"] into tMaskingKey
      
      // UNMASK THE PAYLOAD IF NECESSARY
      if tMasked then
         put __WebSocketMaskUnmaskData(tPayload, tMaskingKey) into tUnmaskedPayload
      else
         put tPayload into tUnmaskedPayload
      end if
      
      // HANDLE THE FRAME BASED ON ITS OPCODE
      switch tOpcode
         case 0 // CONTINUATION FRAME
            // APPEND TO FRAGMENTED MESSAGE
            put tUnmaskedPayload after sWebSocketConnections[pSocketID]["fragmentedMessage"]
            if tFIN then
               // COMPLETE MESSAGE RECEIVED
               dispatch "websocketHandleMessage" to me with pSocketID, sWebSocketConnections[pSocketID]["fragmentedMessage"], sWebSocketConnections[pSocketID]["fragmentedOpcode"]
               put empty into sWebSocketConnections[pSocketID]["fragmentedMessage"]
               put empty into sWebSocketConnections[pSocketID]["fragmentedOpcode"]
            end if
            break
         case 1 // TEXT FRAME
         case 2 // BINARY FRAME
            if tFIN then
               // COMPLETE MESSAGE IN A SINGLE FRAME
               dispatch "websocketHandleMessage" to me with pSocketID, tUnmaskedPayload, tOpcode
            else
               // START OF A FRAGMENTED MESSAGE
               put tUnmaskedPayload into sWebSocketConnections[pSocketID]["fragmentedMessage"]
               put tOpcode into sWebSocketConnections[pSocketID]["fragmentedOpcode"]
            end if
            break
         case 8 // CLOSE FRAME
            __WebSocketHandleClose pSocketID, tUnmaskedPayload
            break
         case 9 // PING FRAME
            __WebSocketHandlePing pSocketID, tUnmaskedPayload
            break
         case 10 // PONG FRAME
            __WebSocketHandlePong pSocketID, tUnmaskedPayload
            break
         default
            // UNKNOWN OPCODE
            put "Unknown WebSocket opcode:" && tOpcode into tError
            __WebSocketHandleError pSocketID, tError
      end switch
      
      // REMOVE THE PROCESSED FRAME FROM THE BUFFER
      delete char 1 to tFrame["length"] of sWebSocketConnections[pSocketID]["buffer"]
   end repeat
   
   // UPDATE LAST ACTIVITY TIMESTAMP
   put the milliseconds into sWebSocketConnections[pSocketID]["lastActivity"]
   
   // CONTINUE READING FROM THE SOCKET
   read from socket pSocketID with message "__WebSocketReceive"
end __WebSocketReceive
