#!/usr/bin/python

# ITM to gprof converter
# Copyright 2016 Alexandre Bailon
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

class Gprof(ITMDecode):
	GMON_MAGIC 		= "gmon"
	GMON_VERSION    	= 1

	GMON_TAG_TIME_HIST	= 0
	GMON_TAG_CG_ARC		= 1
	GMON_TAG_BB_COUNT	= 2

	HISTCOUNTER		= calcsize("H")

	CALLEE_PC_STIMULUS	= 2
	CALLER_PC_STIMULUS	= 3

	def __init__(self):
		# count pc sample
		self.pc_sample = {}
		# arc table
		self.arc = {}
		# pc of caller
		self.from_pc = 0

	def arc_add(self, pc):
		frompc = self.from_pc
		if frompc not in self.arc:
			self.arc[frompc] = {}
		if pc not in self.arc[frompc]:
			self.arc[frompc][pc] = 0
		self.arc[frompc][pc] += 1

	def pc_sample_handler(self, pc):
		if pc not in self.pc_sample:
			self.pc_sample[pc] = 0
		self.pc_sample[pc] += 1

	def instr_handler(self, stimulus, data):
		# SW PC address
		if stimulus == self.CALLEE_PC_STIMULUS:
			if self.from_pc != 0:
				self.arc_add(data)
				self.from_pc = 0
			else:
				self.pc_sample_handler(data)
		# SW From PC address
		if stimulus == self.CALLER_PC_STIMULUS:
			self.from_pc = data

	def write_header(self, f):
		hdr = pack("4si12x", self.GMON_MAGIC, self.GMON_VERSION)
		f.write(hdr)

	def write_arc_record(self, f, frompc, pc, count):
		record = pack("=B3I", self.GMON_TAG_CG_ARC,
					frompc, pc, count)
		f.write(record)

	def write_arc_records(self, f):
		for frompc in self.arc:
			for pc in self.arc[frompc]:
				count = self.arc[frompc][pc]
				self.write_arc_record(f, frompc, pc, count)

	def write_histogram_record(self, f):
		lowpc = 0x08000000
		highpc = 0x08100000
		histsize = (highpc - lowpc) / self.HISTCOUNTER
		profrate = 1000
		hist = []
		test = 0
		for i in range(histsize):
			hist.append(0)
		for pc in self.pc_sample:
			if pc < lowpc:
				continue
			if pc >= highpc:
				continue
			hist[(pc - lowpc) / self.HISTCOUNTER] += self.pc_sample[pc]
		hdr = pack("=B2I2i15sc", self.GMON_TAG_TIME_HIST,
				lowpc, highpc, histsize,
				profrate, "seconds", "s")
		f.write(hdr)
		for i in range(histsize):
			f.write(pack("H", hist[i]))

	def write(self, f):
		self.write_header(f)
		self.write_histogram_record(f)
		self.write_arc_records(f)

def help(res):
	print 'gprof.py -i <swo_trace_file> [-o <gmon_file>]'
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
		elif opt == "-o":
			gmon_file = arg

	if swo_file == '' or gmon_file == '':
		help(2)

	gprof = Gprof()
	gprof.read(swo_file)

	f = open("gmon.out", "w")
	gprof.write(f)
	f.close()

if __name__ == "__main__":
	main(sys.argv[1:])
