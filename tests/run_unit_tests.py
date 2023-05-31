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
	parser.add_argument("--cleartemp", default=True)
	args = parser.parse_args()

	idadir = get_idadir(args.idadir)
	if idadir == "":
		die(f"Failed to get idadir (either IDADIR env variable or --idadir parameter)")

	ida_binary = os.path.join(idadir, "idat.exe")
	if not os.path.exists(ida_binary):
		die(f"Failed to find ida binary at {ida_binary} path")

	phrank_log_filename = args.plog
	temp_filename = None
	if phrank_log_filename is None:
		temp_filename = tempfile.mktemp()
		open(temp_filename, 'a').close()
		phrank_log_filename = temp_filename

	if not os.path.exists(phrank_log_filename):
		die(f"Phrank log file {phrank_log_filename} does not exist")

	test_script = os.path.join(os.path.dirname(__file__), "unit_tests.py")
	call_args = [ida_binary, "-A", "-t", "-S" + test_script + ' ' + phrank_log_filename]
	rv = subprocess.call(call_args)
	if rv != 0:
		die(f"Failed to run script rv={rv}")

	print(f"Successfully run unit tests. Phrank log at {phrank_log_filename}:\n")
	print(open(phrank_log_filename, 'r').read())

	if temp_filename is not None and args.cleartemp is True:
		os.remove(temp_filename)


if __name__ == "__main__":
	main()