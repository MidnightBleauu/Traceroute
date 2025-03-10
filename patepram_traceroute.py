# #################################################################################################################### #
# Imports                                                                                                              #
# Author: Pramit Patel                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #                                                                                                               #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtmlB
    #
    #
    # Citation One: ICMP Python Documentation
    # Implementation inspired by:
    # "icmplib: A powerful library for ICMP networking"
    # Source: https://pypi.org/project/icmplib/
    # Retrieved: [03/05/25]
    #---------------------------------------------------------------------------------------------------------------------
    # Citation Two: Oregon State Canvas
    # Information on ICMP sourced from:
    # "Exploration: The Internet Control Message Protocol (ICMP)" - CS_372_400_W2025
    # Oregon State University Course Material
    # Retrieved: [03/05/25]
    # ################################################################################################################ #
    @staticmethod
    def icmp_helper(icmp_type, icmp_code=None):
        # Dictionary for the ICMP messages
        icmp_type_dict = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            8: "Echo Request",
            11: "Time Exceeded",
        }
        # Dictionary for ICMP code messages
        icmp_code_dict = {
            (3, 0): "Network Unreachable",
            (3, 1): "Host Unreachable",
            (3, 3): "Port Unreachable",
            (11, 0): "TTL Exceeded",
            (11, 1): "Fragment Reassembly Time Exceeded",
        }

        # Get the ICMP type message
        icmp_type_message = icmp_type_dict.get(icmp_type, "Unknown ICMP Type")

        # If ICMP code exists, return type and message
        if icmp_code is not None:
            icmp_code_message = icmp_code_dict.get((icmp_type, icmp_code), "Unknown ICMP Code")
            return f"{icmp_type_message} - {icmp_code_message}"

        # Return only type message if no code
        return icmp_type_message




    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #                                                                                                      #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live

        __DEBUG_IcmpPacket = False      # Allows for debug output


        __recvPacket = b''
        __isValidResponse = False

        # New validity flags for individual fields ###
        __IcmpIdentifier_isValid = False
        __IcmpSequenceNumber_isValid = False
        __IcmpData_isValid = False

        def __init__(self):
            pass

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #                                                                                                            #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

    # New Getters ---------------------------------
        # Checks  if identifier is valid
        def getIcmpIdentifier_isValid(self):
            return self.__IcmpIdentifier_isValid
        # Checks for sequence number valid
        def getIcmpSequenceNumber_isValid(self):
            return self.__IcmpSequenceNumber_isValid
        # checks for data is valid by matching sent request
        def getIcmpData_isValid(self):
            return self.__IcmpData_isValid


        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #                                                                                                           #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

    # Added Setters to assist in validation flag check ----
        # Marks if identifier is valid
        def setIcmpIdentifier_isValid(self, value):
            self.__IcmpIdentifier_isValid = value

        def setIcmpSequenceNumber_isValid(self, value):
            self.__IcmpSequenceNumber_isValid = value

        def setIcmpData_isValid(self, value):
            self.__IcmpData_isValid = value

        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue



        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #                                                                                                            #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        # Modified
        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Returned values from the echo request (original ping)
            ret_sequence = self.getPacketSequenceNumber()
            ret_id = self.getPacketIdentifier()
            ret_data = self.getDataRaw()

            # Values obtained from the echo reply packet
            real_sequence = icmpReplyPacket.getIcmpSequenceNumber()
            real_id = icmpReplyPacket.getIcmpIdentifier()
            real_data = icmpReplyPacket.getIcmpData()

            # Compare teh values
            comp_sequenceValid = (ret_sequence == real_sequence)
            comp_identifierValid = (ret_id == real_id)
            comp_dataValid = (ret_data == real_data)

            # Place Holder for debug statements to verify it working correctly
            print(f"DEBUG STATEMENT - Expected Sequeunce Number: {ret_sequence}, Received: {real_sequence}, Valid: {comp_sequenceValid}")
            print(f"DEBUG STATEMENT - Expected ID : {ret_id}, Received: {real_id}, Valid: {comp_identifierValid}")
            print(f"DEBUG STATEMENT - Raw Data Expected:  {ret_data}, Received: {real_data}, Valid: {comp_dataValid}")

            # Uses the setter flags in the echo reply packet using your setters
            icmpReplyPacket.setIcmpSequenceNumber_isValid(comp_sequenceValid)
            icmpReplyPacket.setIcmpIdentifier_isValid(comp_identifierValid)
            icmpReplyPacket.setIcmpData_isValid(comp_dataValid)

            # Set the valid response flag only if all fields are valid
            overallValidity = comp_sequenceValid and comp_identifierValid and comp_dataValid
            icmpReplyPacket.setIsValidResponse(overallValidity)

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #                                                                                                           #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        # Modified sendEchoRequest to return RTT stats
        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if not whatReady[0]:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:                          # Time Exceeded
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              )

                    elif icmpType == 3:                         # Destination Unreachable
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )

                    elif icmpType == 0:  # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        rtt = icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)
                        return rtt  # Return RTT so it can be used in ping statistics

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #                                                                                                                #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #                                                                                                       #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #                                                                                                            #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #                                                                                                        #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

            # New validity flags for individual fields

        __IcmpIdentifier_isValid = False
        __IcmpSequenceNumber_isValid = False
        __IcmpData_isValid = False

        # New getters for the validity flags
        def getIcmpIdentifier_isValid(self):
            return self.__IcmpIdentifier_isValid

        def getIcmpSequenceNumber_isValid(self):
            return self.__IcmpSequenceNumber_isValid

        def getIcmpData_isValid(self):
            return self.__IcmpData_isValid

        # New setters for the validity flags
        def setIcmpIdentifier_isValid(self, value):
            self.__IcmpIdentifier_isValid = value

        def setIcmpSequenceNumber_isValid(self, value):
            self.__IcmpSequenceNumber_isValid = value

        def setIcmpData_isValid(self, value):
            self.__IcmpData_isValid = value

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #                                                                                                           #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #                                                                                                         #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            rtt = (timeReceived - timeSent) * 1000


            icmp_type = self.getIcmpType()
            icmp_code = self.getIcmpCode()

            icmp_message = IcmpHelperLibrary.icmp_helper(icmp_type, icmp_code)

            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                 )
            return rtt

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #                                                                                                               #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #                                                                                                           #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #                                                                                                              #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()                                                # Build IP

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

    # ################################################################################################################ #
    # Citation Four: Inspired by RedNafi
    # "Implement Traceroute in Python"
    # Source: https://rednafi.com/python/implement_traceroute_in_python/
    # Retrieved: [02/28/25]
    # ################################################################################################################ #

    # Modified function to sent handle the ICMP request and TTL value

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        # Added code Starts Here
        maxHops = 30  # Max Hops defined for a traceroute
        timeoutPerHop = 2  # Time out

        # For loop to begin process for TTL and trace route (# Citation Four: Inspired by RedNafi)
        for ttl in range(1, maxHops + 1):
            # Build teh ICMP packet for the curr TTL
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            # Generates a rand id
            randomIdentifier = (os.getpid() & 0xffff)
            packetIdentifier = randomIdentifier
            packetSequenceNumber = ttl  #Packet sequence is defined as TTL

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)
            icmpPacket.setIcmpTarget(host)
            icmpPacket.setTtl(ttl)
            print(f"TTL={ttl}", end="  ")  # displays the TTL

            # Creates a raw socket and sends  teh packet
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(timeoutPerHop)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', icmpPacket.getTtl()))

            try:
                startTime = time.time()
                mySocket.sendto(b''.join([icmpPacket._IcmpPacket__header, icmpPacket._IcmpPacket__data]),
                                (icmpPacket._IcmpPacket__destinationIpAddress, 0))

                # Waits for response within timeout window
                socketsReady = select.select([mySocket], [], [], timeoutPerHop)
                endTime = time.time()
                elapsedTime = (endTime - startTime)

                # if there is no resposne prints time out msg
                if not socketsReady[0]:
                    print("Request timed out. ")
                    continue

                recvPacket, addr = mySocket.recvfrom(1024)  # Receivest packet from hop
                timeReceived = time.time()
                remainingTime = timeoutPerHop - elapsedTime
                if remainingTime <= 0:
                    print("Request timed out. ")
                    continue

                # Grabs the ICMP types + code
                icmpType, icmpCode = recvPacket[20:22]
                icmpType = int(icmpType)
                icmpCode = int(icmpCode)

                # Displays the stats
                rtt = (timeReceived - startTime) * 1000
                print(f"RTT={int(rtt)} ms   Type={icmpType}   Code={icmpCode}   {addr[0]}", end="  ")

                # If reply is 0 that means we've reached the destination
                if icmpType == 0:
                    print("\nDestination has been reached!")
                    mySocket.close()
                    break

                elif icmpType == 11:
                    print("(Time Exceeded)")
                elif icmpType == 3:
                    print("(Destination Unreachable)")
                else:
                    print("(Unknown response)")

            except timeout:
                print("Request timed out.")
            finally:
                mySocket.close()
    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions
    #
    # Citation Three: GeeksForGeeks
    #  Implementation inspired by:
    # "Traceroute Implementation in Python"
    # Source: https://www.geeksforgeeks.org/traceroute-implementation-on-python/
    # Retrieved: 02/28/25
    #                                                                                                                  #                                                                                                               #
    # ################################################################################################################ #

    # Helper function that assists in the process of printing the RTT statistics after ICMP echo requests
    def printing_stats_helper(self, rtt_list, packets_sent):
        packets_received = len(rtt_list) # counts # of packets received

        # if the packets are greater than zero then
        if packets_received > 0:
            rtt_minVal = min(rtt_list)   # calculates min rtt
            rtt_maxVal = max(rtt_list)   # cals max rtt
            rtt_avgVal = sum(rtt_list) / packets_received # calcualtes the average
            packet_lossed = ((packets_sent - packets_received) / packets_sent) * 100 # gets the percentage of packet loss

            print("\n Ping Statistics : Min, Max, Average, Loss. ")
            print(
                f"Packets Sent = {packets_sent}, Received = {packets_received}, Lost = {packets_sent - packets_received} ({packet_lossed:.2f}% loss)")
            print(f"RTT: Min = {rtt_minVal:.2f} ms, Max = {rtt_maxVal:.2f} ms, Avg = {rtt_avgVal:.2f} ms\n")
        else:
            print("\nNo Packets received. 100% packet loss.\n")

    # Modified Send Ping to store RTT values and calls helper funciton to print the RTT stats
    def sendPing(self, targetHost):
        print(f"Pinging {targetHost}...\n")

        rtt_list = []  # Store RTT values
        packets_sent = 4  # Number of packets sent

        for i in range(packets_sent):
            icmpPacket = IcmpHelperLibrary.IcmpPacket()
            packetIdentifier = (os.getpid() & 0xffff)
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)
            icmpPacket.setIcmpTarget(targetHost)

            rtt = icmpPacket.sendEchoRequest()  # returns RTT
            if rtt is not None:
                rtt_list.append(rtt)
        self.printing_stats_helper(rtt_list, packets_sent) # calls helper funciton to print stats

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)

# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #                                                                                                                   #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    icmpHelperPing.sendPing("209.233.126.254")
    icmpHelperPing.sendPing("www.google.com")
    icmpHelperPing.sendPing("gaia.cs.umass.edu")
    icmpHelperPing.traceRoute("164.151.129.20")
    icmpHelperPing.traceRoute("122.56.99.243")

    # Japan Ping Test
    icmpHelperPing.sendPing("www3.nhk.or.jp")
    icmpHelperPing.traceRoute("www3.nhk.or.jp")

    # UK Ping/ EU
    icmpHelperPing.sendPing("www.bbc.co.uk")
    icmpHelperPing.traceRoute("www.bbc.co.uk")



if __name__ == "__main__":
    main()
