#!/usr/bin/python

# SWO Viewer
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
import getopt
from itm import *

class SWOViewer(ITMDecode):
	PRINTF_STIMULUS	= 0

	def sync_handler(self):
		print "Sync"
	def overflow_handler(self):
		print "Overflow"
	def extension_handler(self):
		print "Extension"
	def timestamp_handler(self, tc, ts):
		print "Time Stamp:" + str(ts)
	def event_handler(self, cyc, fold, lsu, sleep, exc, cpi):
		print "Counter overflow:",
		if cyc:
			print "Cycle",
		if fold:
			print "Fold",
		if lsu:
			print "LSU",
		if sleep:
			print "Sleep",
		if exc:
			print "Exception",
		if cpi:
			print "CPI",
		print ""
	def exception_handler(self, irqn, fn):
		print "Exception:",
		if fn == self.EXCEPTION_ENTRY:
			print "entry to",
		elif fn == self.EXCEPTION_EXIT:
			print "exit from",
		elif fn == self.EXCEPTION_RETURN:
			print "return to",
		print str(irqn) + ""
	def pc_sample_handler(self, pc):
		print "PC Sample",
		print hex(pc)
	def data_trace_pc_handler(self, pc):
		print "DATA trace PC:",
		print hex(pc)
	def data_trace_address_handler(self, address):
		print "DATA trace address offset:",
		print hex(address)
	def data_trace_value_handler(self, value):
		print "DATA trace value:",
		print hex(value)
	def instr_handler(self, stimulus, data):
		if stimulus == self.PRINTF_STIMULUS:
			sys.stdout.write(chr(data))
		else:
			print "SW",
			print hex(stimulus),
			print hex(data)

def help(res):
	print 'gprof.py -i <swo_trace_file>'
	sys.exit(res)

def main(argv):
	debug = 0;
	swo_file = ''
	gmon_file = 'gmon.out'
	try:
		opts, args = getopt.getopt(argv,"hdi:m:")
	except getopt.GetoptError:
		help(2)
	for opt, arg in opts:
		if opt == '-h':
			help(0)
		elif opt == '-d':
			debug = 1
		elif opt == "-i":
			swo_file = arg

	if swo_file == '':
		help(2)

	swo_viewer = SWOViewer()
	swo_viewer.read(swo_file)

if __name__ == "__main__":
	main(sys.argv[1:])
