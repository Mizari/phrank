import idaapi
import phrank_api

analyzer = phrank_api.ASTAnalyzer()
for fea in phrank_api.iterate_all_functions():
	try:
		cfunc = idaapi.decompile(fea)
	except:
		print("failed to decompile", idaapi.get_name(fea))
		continue

	aa = analyzer.analyze_cfunc(cfunc)
	if len(aa.unknown_asgs) == 0:
		continue

	print("got", len(aa.unknown_asgs), "unknown assignments in", idaapi.get_name(fea))
	for asg in aa.unknown_asgs:
		print("  ", asg.x.opname)