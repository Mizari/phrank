import idaapi
import idc
import phrank_api


def main():
	idaapi.auto_wait()

	log_file = idc.ARGV[1]
	phrank_api.set_log_file(log_file)
	phrank_api.log_critical(f"generic tests finished")

	idaapi.qexit(0)


if __name__ == "__main__":
	main()