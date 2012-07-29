# Copyright (C) 2012  tdubourg, License: see LICENSE file in same folder

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License v3
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# import mutex
import collections
import threading
from datetime import datetime
import struct
import binhex
import socket
import subprocess
import re
import sys
import base64
import hashlib

MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
MASKKEY_N_BITS = 4
PAYLOADLENGTH_MAX_EXT_N_BITS = 8
HANDSHAKE = 'HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: {1}\r\n\
Sec-WebSocket-Protocol: chat\r\n\
\r\n'


# For testing purpose, simple response from server: 
def serverCallback(final, opcode, masked, maskKey, payloadLength, payloadData):
	return subprocess.check_output(["top", "-bn1"])


# Utilities functions:

# Function that returns the binary representation of something, as a string, for display purpose
bstr = lambda n, l=16: n<0 and binarystr((2L<<l)+n) or n and bstr(n>>1).lstrip('0')+str(n&1) or '0'

# Another print as binary function
def printAsBinary(data):
	print " ".join([bin(ord(c)) for c in data])
	
# Yet another one
def printAsBinary2(data):
	print " ".join([bin(c) for c in data])

# Generate the answer key for the handshake using the key sent from the client
def generateAnswerKey(key):
	return base64.b64encode(hashlib.sha1(key + MAGIC_STRING).digest())

# Extract the key from the handshake
def get_key_from_handshake(hs):
	r = re.compile("(.*?)Sec\-WebSocket-Key: (.*?)\r?\n(.*?)")
	m = r.search(hs)
	key = m.group(2)
	return key
	
# Decompose the binary frame sent from a client into the different part of the frame: 
# final: true/false. Flag saying if the current frame was the last of the message or not
# opcode: opcode of the frame... see RFC norm paper for more details
# masked: true/false. Flag saying if the data in this frame has been masked or not
# maskKey: if the data in this frame is masked, this variable will contain the maskKey under its binary form
# payloadLength: Length of the actual data/message in this frame ("payLoad")
# payloadData: finally, the actual payLoadData, that is to say, the message we are interested in. IT IS NOT UNMASKED automatically. If the masked flag is True then use the unmask() function for reading the payLoadData
def decomposeFrame(rawFrame):
	dbg = False
	
	if dbg:
		print 'Entering decomposeFrame.'
	frame = [ord(c) for c in rawFrame]
	if not frame:
		return None, None, None, None, None, None
	
	if dbg:
		print 'FrameToIntegers: ', frame
	
	maskKey = None
	
	if ((frame[0] & 0b10000000) >> 7) == 1: #keeping only the first bit
		final = True
	else:
		final = False
	
	if dbg:
		print 'Final: ', final
	
	opcode = frame[0] & 0b01111111 #masking the first bit
	
	if dbg:
		print 'Opcode: ', opcode
	
	if ((frame[1] & 0b10000000) >> 7) == 1: #keeping only the first bit
		masked = True
	else:
		masked = False
		
	if dbg:
		print 'Masked data? ', masked
	
	payloadLength = frame[1] & 0b01111111 #masking the first bit
	
	payloadDataStartIndex = 2
	
	if payloadLength == 126: # then the payloadLength is on 16 bits in the Extended Payload part
		payloadLength = (frame[2] << 8) + frame[3] # 2 bytes interpreted as 16 bits (2 bytes) unsigned integer
		payloadDataStartIndex += 2
	elif payloadLength == 127: # then the payloadLength is on 64 bits in the Extended Payload part
		i = 1
		payloadLength = 0
		payloadDataStartIndex += 8
		while i < (PAYLOADLENGTH_MAX_EXT_N_BITS+1):
			payloadLength += frame[1+i] << (8*(PAYLOADLENGTH_MAX_EXT_N_BITS-i)) # 2 bytes interpreted as 64 bits (8 bytes) unsigned integer
			# note : we add each byte, positionning it as shifted to the leftsee as binary of the number of bits * the number of Bytes still to be read (8-1))
			i += 1
	
	if dbg:
		print 'payloadLength: ', payloadLength
	
	if masked:
		i = 0
		maskKey = []
		while i < MASKKEY_N_BITS:
			maskKey.append(frame[payloadDataStartIndex+i])# << (8*(MASKKEY_N_BITS-i-1)))
			i += 1
		payloadDataStartIndex += 4
		
	if dbg:
		print 'maskKey: ', maskKey
	
	i = 0
	payloadData = []
	while i < payloadLength: # for all the remaining bytes, we concatenate and store in as the payLoadData
		payloadData.append(frame[payloadDataStartIndex+i])# << (8*(payloadLength-i-1))) # same tip as for payloadLength, see above
		i += 1
	
	if dbg:
		print 'payloadData: ', payloadData
	
	return (final, opcode, masked, maskKey, payloadLength, payloadData)
	
# Create the frame to sent to the client for sending a string message "data"
# It uses the final flag each time and always the "text" opcode. You can customize the function if you need...
# It may or may not work with non-ascii chars... up to you to test
def composeTxtFrame(data):
	bytes = bytearray()
	bytes.append(0b10000001)
	header = 0b100000010 # final message + 000 + opcode Text + non masked
	payloadLength = len(data)
	# print 'Length of data is', payloadLength
	payloadLengthNOfBits = 4
	if payloadLength > 65535: # 2^16-1
		NBYTESOFPLLENGTH = 8
		payloadLengthNOfBits += NBYTESOFPLLENGTH
		bytes.append(127 + 0)
		i = 0
		while i < NBYTESOFPLLENGTH:
			bytes.append((payloadLength >> (8*(NBYTESOFPLLENGTH-i-1))) & 255)
			i += 1
		
	elif payloadLength > 125:
		print 'Coding payloadLength on 16 bits'
		NBYTESOFPLLENGTH = 2
		payloadLengthNOfBits += 16
		bytes.append(126 + 0)
		i = 0
		dbgarr = bytearray()
		while i < NBYTESOFPLLENGTH:
			shift = (8*(NBYTESOFPLLENGTH-i-1))
			print 'Shifting of', shift
			b = (payloadLength >> shift) & 255
			dbgarr.append(b)
			bytes.append(b)
			i += 1
		print 'payloadLength coded as: '
		printAsBinary2(dbgarr)
		
	else:
		bytes.append(payloadLength + 0)
	
	for c in data:
		bytes.append(c)
	
	return bytes

def unmask(data, maskKey):
	dbg = False
	if dbg:
		print 'Entering unmask'
		print 'Data:', data
		print 'MaskKey:', maskKey
	
	if data is None or maskKey is None:
		return ''
	
	unmasked = ''
	i = 0
	for c in data:
		#unmasked += (struct.pack('I', c ^ maskKey[i % MASKKEY_N_BITS]))
		if dbg:
			print bin(c)
			print bin(maskKey[i % MASKKEY_N_BITS])
			print c ^ maskKey[i % MASKKEY_N_BITS]
		unmasked += chr(c ^ maskKey[i % MASKKEY_N_BITS])
		i += 1
	return unmasked
		
class MyServer:
	def __init__(self, port, callback):
		self.port = port
		self.s = MySocket()
		self.treatmentCallback = callback
	
	def start(self):
		self.s.setCallback(self.onConnect)
		self.s.listen(self.port)

		
	def onConnect(self, conn, addr):
		dbg = False
		
		if dbg:
			print 'Server callback called !'
			
		sock = MySocket(conn)
		header = ''

		handshaken = False
		while True:
			if handshaken == False:
				
				header += sock.recv_end('\r\n\r\n')
				if not header:
					break
				if dbg:
					print 'Header: '
					print header
				
				handshake = HANDSHAKE.replace('{1}', generateAnswerKey(get_key_from_handshake(header)))
				sock.sendall(handshake)
				handshaken = True
				if dbg:
					print 'Handshake terminated'
			else:
				data = conn.recv(128)
				t1 = datetime.now()
				if not data:
					print 'Host disconnected.'
					break
				
				if dbg:
					print 'Data read from ', addr, ': ', data
					printAsBinary(data)
					print 'Frame decomposition: '
				
				t12 = datetime.now()
				final, opcode, masked, maskKey, payloadLength, payloadData = decomposeFrame(data)
				
				if dbg:
					print 'decomposeFrame took', ((t12 - datetime.now()).microseconds), 'us'
					print 'Unmasking:', unmask(payloadData, maskKey)
				
				toSend = self.treatmentCallback(final, opcode, masked, maskKey, payloadLength, payloadData);

				if dbg:
					print 'Length of data to send: ', len(toSend)

				if dbg:
					t13 = datetime.now()
				
				send = composeTxtFrame(toSend + '\r\n\r\n')
				
				if dbg:
					print 'composeTxtFrame took', ((t13 - datetime.now()).microseconds), 'us'
				
				if dbg:
					print send
					
				try:
					conn.sendall(send) 
				except socket.error, e:
					print e
					break
		
		print 'Conection closed to ', addr
		conn.close()
	


class MySocket:
	def __init__(self, sock=None, p=None):
		if sock is None:
			self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
		else:
			print 'Init MySocket with existing socket'
			self.s = sock
			
		if p is not None:
			self.p = p
			
	def connect(self, host, port=None):
		if port is None and p is not None:
			self.s.connect(host, p)
		else:	
			self.s.connect(host, port)
			
	def setCallback(self, callback):
		self.callback = callback
			
	def listen(self, port=None):
		if port is not None:
			self.p = port
		
		self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.s.bind(('', self.p))
		# print 'Listening on port ', self.p
		self.s.listen(1024)
		while True:
			conn, addr = self.s.accept()
			# print 'Connected by ', addr
			# self.callback(conn, addr)
			t = threading.Thread(target=self.callback, args=(conn, addr))
			t.daemon = True
			t.start()

	def recv_end(self, end):
		# print 'recv_end() entered'
		total_data=[];data=''
		while True:
				data=self.s.recv(8192)
				if end in data:
					total_data.append(data[:data.find(end)])
					break
				total_data.append(data)
				if len(total_data)>1:
					#check if end_of_data was split
					last_pair=total_data[-2]+total_data[-1]
					if end in last_pair:
						total_data[-2]=last_pair[:last_pair.find(End)]
						total_data.pop()
						break
		# print 'recv_end() exited'
		return ''.join(total_data)
	def sendall(self, data):
		self.s.sendall(data)

			
			
print 'Programs begins' 

server = MyServer(8080, serverCallback)
server.start();

print 'Programs ends'
