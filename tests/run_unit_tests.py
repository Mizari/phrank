import os
import tempfile
import subprocess
import argparse


def die(s:str):
	print(s)
	exit(1)


def get_idadir(args_idadir):
	if args_idadir is not None: return args_idadir
	idadir = os.environ.get("IDADIR")
	if idadir is not None: return idadir
	return ""


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--idadir", help="IDA Pro directory")
	parser.add_argument("--plog", help="phrank log file")
	args = parser.parse_args()

	idadir = get_idadir(args.idadir)
	if idadir == "":
		die(f"Failed to get idadir (either IDADIR env variable or --idadir parameter)")

	ida_binary = os.path.join(idadir, "idat.exe")
	if not os.path.exists(ida_binary):
		die(f"Failed to find ida binary at {ida_binary} path")

	phrank_log_file = args.plog
	if phrank_log_file is None:
		phrank_log_file = tempfile.mktemp()
		open(phrank_log_file, 'a').close()

	if not os.path.exists(phrank_log_file):
		die(f"Phrank log file {phrank_log_file} does not exist")

	test_script = os.path.join(os.path.dirname(__file__), "unit_tests.py")
	call_args = [ida_binary, "-A", "-t", "-S" + test_script + ' ' + phrank_log_file]
	rv = subprocess.call(call_args)
	if rv != 0:
		die(f"Failed to run script rv={rv}")

	print(f"Successfully run unit tests. Phrank log at {phrank_log_file}:\n")
	print(open(phrank_log_file, 'r').read())


if __name__ == "__main__":
	main()