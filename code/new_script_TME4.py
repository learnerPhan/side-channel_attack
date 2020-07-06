import chipwhisperer.capture.ChipWhispererCapture as cwc
from PySide.QtCore import *
from PySide.QtGui import *
import sys

import time
from Crypto.Cipher import AES
import csv
import binascii
import random


def hexStrToByteArray(hexStr):
	ba = bytearray()
	for s in hexStr.split():
		ba.append(int(s, 16))
	return ba

def pe():
	QCoreApplication.processEvents()

#Make the application and get the main module
app = cwc.makeApplication()
cap = cwc.ChipWhispererCapture()

#Setting the OpenADC Interface
cmds=[['Generic Settings', 'Scope Module', 'ChipWhisperer/OpenADC'],
['Generic Settings', 'Target Module', 'Simple Serial'],
['Generic Settings', 'Trace Format', 'ChipWhisperer/Native'],
['OpenADC Interface', 'connection', 'ChipWhisperer Lite'],
['Target Connection', 'connection', 'ChipWhisperer-Lite']
]
for cmd in cmds: cap.setParameter(cmd)

#Connect to scope
cap.doConDisScope(True)
pe()

#Setting the Scope
cmds = [  ['CW Extra', 'CW Extra Settings', 'Trigger Pins', 'Target IO4 (Trigger Line)', True],
['CW Extra', 'CW Extra Settings', 'Target IOn Pins', 'Target IO1', 'Serial RXD'],
['CW Extra', 'CW Extra Settings', 'Target IOn Pins', 'Target IO2', 'Serial TXD'],
      ['OpenADC', 'Clock Setup', 'CLKGEN Settings', 'Desired Frequency', 7370000.0],
['CW Extra', 'CW Extra Settings', 'Target HS IO-Out', 'CLKGEN'],
['OpenADC', 'Clock Setup', 'ADC Clock', 'Source', 'CLKGEN x4 via DCM'],
      ['OpenADC', 'Trigger Setup', 'Total Samples', 2000],
      ['OpenADC', 'Trigger Setup', 'Offset', 2000],
      ['OpenADC', 'Gain Setting', 'Setting', 45],
      ['OpenADC', 'Trigger Setup', 'Mode', 'rising edge'],
      #Final step: make DCMs relock in case they are lostn

      ['OpenADC', 'Clock Setup', 'ADC Clock', 'Reset ADC DCM', None],
]
for cmd in cmds: cap.setParameter(cmd)
#GettinGetting Started Writing C Code for Atmel XMEGAg Started Writing C Code for Atmel XMEGA

#Connect to serial port to XMEGA
ser = cap.target.driver.ser
ser.con()

# Create a pointer on a csv file
c = csv.writer(open("aes_traces.csv", "wb"))
fbb = csv.writer(open("aes_firstbytebeforesbox.csv","w"))
# Create an AES key To recover By SCA
myaes_key   = hexStrToByteArray("00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF")

# Create an aray that will contain the AES input
myaes_input = bytearray(16)

# Create the null message
trylist = "abcdefghijklmnopqrstuvwyx0123456789"
# Create an object cipher for AES in ECB mode, and parameterized with myaes_key
cipher = AES.new(str(myaes_key), AES.MODE_ECB)


# Declarer deux tableux a et b contenant la somme des mesures
#class_belonging contain the class of each input
#[1,0] means 1st input belongs to the g1, 2de to g0 

for j in range(0, 6000):
	for i in range(0, 16):
		myaes_input [i] = random.choice(trylist)

	#Flush clears input buffer
	ser.flush()
	#Sending the key to the XMEGA through the serial
	ser.write("k" + binascii.hexlify(myaes_key) + "\n")
	#Always wait a while after r/w the serial
	time.sleep(0.1)
	#Put the scope on and process event
	cap.scope.arm()
	pe()
	#Sending the plain to the XMEGA through the serial
	ser.write("p" + binascii.hexlify(myaes_input) + "\n")
	time.sleep(0.1)
	# START Measurement Phase
	if cap.scope.capture(update=True, NumberPoints=None, waitingCallback=pe):
		print "Timeout"
	else:
		print "Capture OK"
	# END Measurement Phase

	# Get the answer
	myaes_output = bytearray(cipher.encrypt(str(myaes_input)))

	#Print the key and the plain
	#print "k" + binascii.hexlify(myaes_key)
	#print "p" + binascii.hexlify(myaes_input)

	#Read response, which is 33 bytes long. Specifying length avoids waiting for
	#timeout to occur.
	
	#firstbyte = ser.read(2)
	#time.sleep(0.1)
	#print "premier octet apres premier s-box est :" + firstbyte
	# comparer 1er bit de myaes_input avec celui de firstbyte

	#considerer soit a soit b


	#respdata = ser.read(33)
	#time.sleep(0.1)
	#print "On ATXMega, AES(s,m)= " + respdata
	#Compare with the onsite computation
	#print "Expected Output     = o" + binascii.hexlify(myaes_output)

	#Scope data is contained in scope.datapoints
	#print cap.scope.datapoints
	#print len(cap.scope.datapoints)
	# Write the measurements in the CSV file
	c.writerow(myaes_input)
	c.writerow(cap.scope.datapoints)
	#c.writerow('\n')
	#firstbytebefore = binascii.hexlify(myaes_input)[:2]
	#fbb.writerow([firstbytebefore])
#The following should delete the CWC Main window and disconnect
#where appropriate
cap.deleteLater()
sys.exit(app.exec_())
