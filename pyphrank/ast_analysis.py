from pyphrank.ast_parts import SExpr, ASTCtx, CallCast, TypeCast, Var, VarUseChain


def extract_implicit_calls(sexpr:SExpr):
	if sexpr.is_implicit_call():
		yield sexpr


def extract_var_reads(sexpr:SExpr):
	if sexpr.is_var_use_chain():
		yield sexpr.var_use_chain

	if sexpr.is_assign():
		# dont add target var_use_chain to reads, because it is write
		# if its not var_use_chain, then it gets added to reads there
		if not sexpr.target.is_var_use_chain():
			yield from extract_var_reads(sexpr.target)

		# var_use_chain value IS a read though
		yield from extract_var_reads(sexpr.value)

	if sexpr.is_binary_op():
		yield from extract_var_reads(sexpr.x)
		yield from extract_var_reads(sexpr.y)

	if sexpr.is_bool_op():
		yield from extract_var_reads(sexpr.x)
		yield from extract_var_reads(sexpr.y)


def extract_implicit_calls(sexpr:SExpr):
	# TODO in binary ops
	# in assigns
	return


class ASTAnalysis():
	def __init__(self, actx:ASTCtx):
		self.actx = actx

		self.returns : list[SExpr] = []
		self.sexprs : list[SExpr] = []
		self.call_casts : list[CallCast] = []
		self.type_casts: list[TypeCast] = []

	def iterate_returns(self):
		for r in self.returns:
			yield r

	def iterate_call_casts(self):
		for c in self.call_casts:
			yield c

	def iterate_type_casts(self):
		for c in self.type_casts:
			yield c

	def iterate_implicit_calls(self):
		for c in self.sexprs:
			yield from extract_implicit_calls(c)

		for r in self.returns:
			yield from extract_implicit_calls(r)

		for c in self.call_casts:
			yield from extract_implicit_calls(c.arg)

		for t in self.type_casts:
			yield from extract_implicit_calls(t.arg)

	def iterate_assigns(self):
		for sexpr in self.sexprs:
			if sexpr.is_assign():
				yield sexpr

	def iterate_var_reads(self):
		for s in self.sexprs:
			yield from extract_var_reads(s)

		for r in self.returns:
			yield from extract_var_reads(r)

		for c in self.call_casts:
			# direct var use chain casts are casts, not reads
			if not c.arg.is_var_use_chain():
				yield from extract_var_reads(c.arg)

		for t in self.type_casts:
			# direct var use chain casts are casts, not reads
			if not t.arg.is_var_use_chain():
				yield from extract_var_reads(t.arg)