# ITMDecode Library 
# Copyright (C) 2016  BayLibre
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# 
# Author: Alexandre Bailon <abailon@baylibre.com>

import sys
from struct import *

class ITMPacket:

	SYNC_PACKET			= 0
	OVERFLOW_PACKET			= 1
	TIMESTAMP_PACKET		= 2
	EXTENSION_PACKET		= 3
	RESERVED_PACKET			= 4
	INSTR_PACKET			= 5
	HW_PACKET			= 6

	ADDRESS_MASK			= 0xf8
	ADDRESS_OFFSET			= 3
	SOURCE_MASK			= 0x04
	SOURCE_OFFSET			= 2
	SOURCE_HW			= 1
	SOURCE_SW			= 0
	SIZE_MASK			= 0x03
	CONTINUATION			= 0x80

	def get_packet_address(self):
		return (self.header & self.ADDRESS_MASK) >> self.ADDRESS_OFFSET

	def get_packet_source(self):
		return (self.header & self.SOURCE_MASK) >> self.SOURCE_OFFSET

	def get_packet_type(self):
		header = self.header
		if header == 0x80 or header == 0:
			return self.SYNC_PACKET
		elif header == 0x70:
			return self.OVERFLOW_PACKET
		elif header & 0x0F == 0 and header & 0xF0 != 0:
			return self.TIMESTAMP_PACKET
		elif header & 0x0F == 0x0C or header & 0x0F == 0x08:
			return self.EXTENSION_PACKET
		elif header & 0x0F == 0x04:
			return self.RESERVED_PACKET
		elif header & 0x04 == 0x00:
			return self.INSTR_PACKET
		else:
			return self.HW_PACKET

	def get_packet_size(self):
		packet = self.get_packet_type()
		if packet == self.SYNC_PACKET:
			return 0
		if packet == self.OVERFLOW_PACKET:
			return 0
		if packet  == self.TIMESTAMP_PACKET:
			if self.header & 0x80:
				return -1
			else:
				return 0
		if packet == self.EXTENSION_PACKET:
			return 0
		if packet == self.RESERVED_PACKET:
			return 0

		size = self.header & self.SIZE_MASK
		if size == 3:
			size = 4

		return size

	def read_header(self, f):
		byte = f.read(1)
		if not byte:
			return -1
		self.header, = unpack("B", byte)
		return 0

	def read_extension_packet(self, f):
		c = 1
		i = 0
		while c != 0:
			byte = f.read(1)
			if not byte:
				return -1
			unpack_byte, = unpack("B", byte)
			self.bytes.append(unpack_byte)
			c = unpack_byte & 0x80
			i += 1
		return i

	def read_data(self, f):
		for i in range(self.size):
			byte = f.read(1)
			if not byte:
				return -1
			unpack_byte, = unpack("B", byte)
			self.bytes.append(unpack_byte)
		return self.size

	def read(self, f):
		if self.read_header(f) < 0:
			return -1
		self.size = self.get_packet_size()
		if self.size == -1:
			self.size = self.read_extension_packet(f)
		else:
			self.size = self.read_data(f)
		return self.size

	def convert_data(self):
		bytes = self.bytes
		if self.size == 1:
			self.data = bytes[0]
		if self.size == 2:
			self.data = bytes[1] << 8 | bytes[0]
		if self.size == 3:
			self.data = bytes[2] << 16 | bytes[1] << 8 | bytes[0]
		if self.size == 4:
			self.data = bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0]

	def __init__(self, f):
		self.size = 0
		self.header = 0
		self.data = 0
		self.bytes = []

		ret = self.read(f)
		if (ret != -1):
			self.convert_data()
		else:
			raise EOFError()

class ITMDecode:
	TIMESTAMP_TC_MASK	= 0x30
	TIMESTAMP_TC_OFFSET	= 4
	TIMESTAMP_TS_MASK	= 0x70
	TIMESTAMP_TS_OFFSET	= 4

	EXCEPTION_NUMBER_MASK	= 0x01ff
	EXCEPTION_FN_MASK	= 0x3000
	EXCEPTION_FN_OFFSET	= 12
	EXCEPTION_ENTRY		= 1
	EXCEPTION_EXIT		= 2
	EXCEPTION_RETURN	= 3

	EVENT_PACKET		= 0
	EVENT_CYC		= 0x20
	EVENT_FOLD		= 0x10
	EVENT_LSU		= 0x08
	EVENT_SLEEP		= 0x04
	EVENT_EXC		= 0x02
	EVENT_CPI		= 0x01

	EXCEPTION_PACKET	= 1
	PC_SAMPLE_PACKET	= 2

	DATA_TRACE_PACKET_MIN	= 8
	DATA_TRACE_PACKET_MAX	= 23
	DATA_TRACE_PC		= [8, 10, 12, 14]
	DATA_TRACE_ADDRESS	= [9, 11, 13, 15]

	def __init__(self):
		# print all trace
		self.debug = 0

	def get_timestamp_tc(self, header):
		tc = header & self.TIMESTAMP_TC_MASK
		return tc >> self.TIMESTAMP_TC_OFFSET

	def get_timestamp_value(self, header, data):
		if header & 0x80:
			ts = 0
			c = 1
			i = 0
			while c != 0:
				ts <<= 7
				ts |= (data >> (8 * i)) & 0x7f
				c = (data >> (8 * i)) & 0x80
				i += 1
			return ts
		else:
			return (header & self.TIMESTAMP_TS_MASK) >> self.TIMESTAMP_TS_OFFSET

	def get_exception_number(self, data):
		return data & self.EXCEPTION_NUMBER_MASK

	def get_exception_fn(self, data):
		return (data & self.EXCEPTION_FN_MASK) >> self.EXCEPTION_FN_OFFSET

	def sync_handler(self):
		return

	def overflow_handler(self):
		return

	def extension_handler(self):
		return

	def timestamp_handler(self, tc, ts):
		return

	def event_handler(self, cyc, fold, lsu, sleep, exc, cpi):
		return

	def exception_handler(self, irqn, fn):
		return

	def pc_sample_handler(self, pc):
		return

	def data_trace_pc_handler(self, pc):
		return

	def data_trace_address_handler(self, address):
		return

	def data_trace_value_handler(self, value):
		return

	def instr_handler(stimulus, data):
		return

	def decode(self, itm_packet):
		header = itm_packet.header
		size = itm_packet.size
		bytes = itm_packet.bytes
		data = itm_packet.data
		packet = itm_packet.get_packet_type()
		address = itm_packet.get_packet_address()
		source = itm_packet.get_packet_source()

		if packet == itm_packet.SYNC_PACKET:
			self.sync_handler()
		elif packet == itm_packet.OVERFLOW_PACKET:
			self.overflow_handler()
		elif packet == itm_packet.EXTENSION_PACKET:
			self.extension_handler()
		elif packet == itm_packet.TIMESTAMP_PACKET:
			if header & 0x80:
				tc = self.get_timestamp_tc(header)
			else:
				tc = -1
			ts = self.get_timestamp_value(header, data)
			self.timestamp_handler(tc, ts)
		elif packet == itm_packet.RESERVED_PACKET:
				print "Reserved"
		elif packet == itm_packet.HW_PACKET:
			if address == self.EVENT_PACKET:
				cyc = data & self.EVENT_CYC
				fold = data & self.EVENT_FOLD
				lsu = data & self.EVENT_LSU
				sleep = data & self.EVENT_SLEEP
				exc = data & self.EVENT_EXC
				cpi = data & self.EVENT_CPI
				self.event_handler(cyc, fold, lsu, sleep, exc, cpi)
			# Exception
			elif address == self.EXCEPTION_PACKET:
				irqn = self.get_exception_number(data)
				fn = self.get_exception_fn(data)
				self.exception_handler(irqn, fn)
			# PC Sample
			elif address == self.PC_SAMPLE_PACKET:
				self.pc_sample_handler(data)
			elif self.DATA_TRACE_PACKET_MIN <= address and address <= self.DATA_TRACE_PACKET_MAX:
				if address in self.DATA_TRACE_PC:
					self.data_trace_pc_handler(data)
				elif address in self.DATA_TRACE_ADDRESS:
					self.data_trace_address_handler(data)
				else:
					self.data_trace_value_handler(data)
			else:
				print "Invalid packet ",
				print hex(header),
				print hex(data)
		elif packet == itm_packet.INSTR_PACKET:
			self.instr_handler(address, data)

	def read(self, filename):
		f = open(filename, 'rb')
		try:
			while 1:
				try:
					packet = ITMPacket(f)
					self.decode(packet)
				except EOFError:
					break
		finally:
			f.close()
