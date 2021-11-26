#!/usr/bin/env python3

import sys
import numpy as np

def fn(n):
	if n < 1000:
		return f"{n} ns"
	if n < 1000000:
		return f"{n/1000.0:.3f} µs"
	if n < 1000000000:
		return f"{n/1000000.0:.3f} ms"
	return f"{n/1000000000.0:.3f} s"

def fncy(n):
	if n < 1000:
		return f"{n}"
	if n < 1000000:
		return f"{n/1000.0:.3f} tsd"
	if n < 1000000000:
		return f"{n/1000000.0:.3f} mil"
	return f"{n/1000000000.0:.3f} bil"

def print_stat(s):
	print(f"{len(s)} samples")
	print(f"avg: {fn(np.average(s))} +- {fn(np.std(s))}")
	sd = [x/10000 for x in s]
	print("/10000 fcts:")
	print(f"avg: {fn(np.average(sd))} +- {fn(np.std(sd))}")

def print_stat_cy(s):
	print(f"{len(s)} samples")
	print(f"avg: {fncy(np.average(s))} +- {fncy(np.std(s))}")
	print(f"avg: {fn(np.average(s)/(1.3))} +- {fn(np.std(s)/(1.3))}")
	sd = [x/10000 for x in s]
	print("/10000 fcts:")
	print(f"avg: {fncy(np.average(sd))} +- {fncy(np.std(sd))}")
	print(f"avg: {fn(np.average(sd)/(1.3))} +- {fn(np.std(sd)/(1.3))}")

def main():

	if len(sys.argv) < 2:
		print(f"Usage: {sys.argv[0]} <file>")
		return

	adds = []
	addcycs = []
	loads = []
	loadcycs = []
	with open(sys.argv[1]) as f:
		content = f.readlines()
		mode = 0
		for line in content:
			if line[0] == 'm':
				continue
			l = line.rstrip('\n').split(',')
			if len(l) <= 1:
				continue
			addms, addcy, loadms, loadcy = l
			adds.append(int(addms))
			addcycs.append(int(addcy))
			loads.append(int(loadms))
			loadcycs.append(int(loadcy))


	print("add:")
	print_stat(adds)
	print_stat_cy(addcycs)
	print("\nload:")
	print_stat(loads)
	print_stat_cy(loadcycs)

if __name__ == '__main__':
	main()
