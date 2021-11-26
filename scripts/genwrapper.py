#!/usr/bin/env python3

import sys

shortArgumentNames = "abcdefghijklmnopqrstuvwxyz"

def main():
	if len(sys.argv) < 2:
		print(f"Usage: {sys.argv[0]} <file>")
		print("")
		print("<file> need to be a file containing a list of function signatures. One signature per line. Arguments need to be delimited by a pipe '|'. Example signature:")
		print("<returntype> <name> [<argumenttype> <argumentname>[|<argumenttype> <argumentname>[...]]]")
		print("void myfunction int someparam|double anotherparam|my_datatype *a_third_param")
		exit(1)

	source = open('dlwrapper.c', 'w');
	header = open('dlwrapper.h', 'w');
	source.write('#include "pa.h"\n');
	with open(sys.argv[1], 'r') as file:
		lines = file.readlines()
		for line in lines:
			rettype, rest = line.split(' ', 1)
			name, rest = rest.split(' ', 1)
			arguments = rest.split('|')
			shortArgumentString = ", ".join([shortArgumentNames[i] for i in range(0, len(arguments))])
			argumentString = (", ".join(arguments)).rstrip()
			argumentNames = (", ".join(list(map(lambda argument: argument.split(' ')[1].lstrip('*'), arguments)))).rstrip()
			header.write(f"#define {name}({shortArgumentString}) __dynamic_{name}({shortArgumentString})\n")
			header.write(f"{rettype} __dynamic_{name}({argumentString});\n")

			source.write(f"{rettype} __dynamic_{name}({argumentString}) {{\n")
			source.write(f"\tp_name = dl_begin_call(\"{name}\");\n")
			if (rettype != "void"):
				source.write(f"\t{rettype} retval;\n");
				source.write(f"\tretval = p_name({argumentNames});\n")
			else:
				source.write(f"\tp_name({argumentNames});\n")
			source.write(f"\tdl_end_call(\"{name}\");\n")
			if (rettype != "void"):
				source.write(f"\treturn retval;\n")
			
			source.write(f"}}\n")

	header.close()
	source.close()

if __name__ == '__main__':
	main()