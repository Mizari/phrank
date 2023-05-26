import idaapi
import idc
import phrank


def main():
	idaapi.auto_wait()

	log_file = idc.ARGV[1]
	phrank.set_log_file(log_file)
	phrank.log_critical(f"unit tests finished")

	idaapi.qexit(0)


if __name__ == "__main__":
	main()