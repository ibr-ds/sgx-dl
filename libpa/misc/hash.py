#!/usr/bin/env python3

import sys
import subprocess

def split_cmd(cmd: str):
    # We want to split the string on spaces but not inside quotes
    # Also we want to stop after we encounter a semicolon

    # First, trim whitespace at start end end
    cmd = cmd.strip(' \t\n')

    # Now iterate through the string
    cmdparts = []
    cur = ''
    inquote = False
    for i in range(0, len(cmd)):
        if inquote:
            c = cmd[i]
            if i == len(cmd) - 1:
                # We are at the end, add the last part
                if len(cur) > 0:
                    cmdparts.append(cur)
                cur = ''
            elif c == '"':
                # We found the closing quote
                inquote = False
            else:
                cur += c

        else:
            c = cmd[i]
            if i == len(cmd)-1:
                # We are add the end, add the last part
                cur += c
                if len(cur) > 0:
                    cmdparts.append(cur)
                cur = ''
            elif c == ' ':
                if len(cur) > 0:
                    cmdparts.append(cur)
                cur = ''
            elif c == '"':
                inquote = True
            else:
                cur += c

    return cmdparts


def execute(cmd: str):
    cmdarr = split_cmd(cmd)
    result = subprocess.run(cmdarr, stdout=subprocess.PIPE)
    encoded = result.stdout.decode(sys.stdout.encoding)
    return result.returncode, encoded.strip('\n')

def hashtoC(hash: str, varname: str):
	s = f"sgx_sha256_hash_t {varname} = {{"

	i = 0
	while i < len(hash):
		if i % 2 == 0:
			s += f"0x{hash[i]}"
		else:
			s += f"{hash[i]}, "
		i += 1

	s = s[:-2] + "};"

	return s


def main():
	if len(sys.argv) < 2:
		print(f"Usage: {sys.argv[0]} <enclave.signed.so>")

	print(f"Hashes for {sys.argv[1]}")

	c, s = execute(f"bash -c \"readelf -x .symtab {sys.argv[1]} | tail -n +3 | head -n -1 | awk '{{print $2$3$4$5}}' | tr -d '\n' | xxd -r -p | sha256sum | awk '{{print $1}}'\"")
	if c != 0:
		print("error hashing")

	print(hashtoC(s, "symhash"))

	c, s = execute(f"bash -c \"readelf -x .strtab {sys.argv[1]} | tail -n +3 | head -n -1 | awk '{{print $2$3$4$5}}' | tr -d '\n' | xxd -r -p | sha256sum | awk '{{print $1}}'\"")
	if c != 0:
		print("error hashing")

	print(hashtoC(s, "strhash"))

if __name__ == "__main__":
	main()
