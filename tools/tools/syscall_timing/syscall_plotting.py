#!/usr/bin/env python3

import sys
import numpy
from matplotlib import pyplot as plt

def main():
	if len(sys.argv) != 2:
		print("usage: " + sys.argv[0] + "file-path")
		sys.exit(1)

	f = open(sys.argv[1]).readlines()
	results = {}
	for l in f:
		l = l.split()
		name_and_size = l[0].split('_')
		benchmark_name = name_and_size[0]
		if len(name_and_size) == 1:
			benchmark_size = 1
		else:
			benchmark_size = int(name_and_size[1])
		iteration = l[1]
		result = l[4]
		if not benchmark_name in results:
			results[benchmark_name] = {}
		if not benchmark_size in results[benchmark_name]:
			results[benchmark_name][benchmark_size] = {}
		results[benchmark_name][benchmark_size][iteration] = float(result)

	plt.xscale('log')
	plt.xlabel('Data size [bytes]')
	plt.yscale('log')
	plt.ylabel('Time [s]')
	
	for benchmark in results:
		large_x = []
		large_y = []
		for x in results[benchmark].keys():
			y_array = [y for y in results[benchmark][x].values()]
			x_array = [x for _ in y_array]
			large_x = large_x + x_array
			large_y = large_y + y_array

		plt.scatter(large_x, large_y, marker='o', label=benchmark)
		plt.legend()

	plt.show()

if __name__ == "__main__":
	main()

