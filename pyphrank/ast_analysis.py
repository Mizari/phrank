from pyphrank.ast_parts import SExpr, ASTCtx, CallCast, TypeCast, VarWrite, Var, VarUses, VarUseChain


class ASTAnalysis():
	def __init__(self, actx:ASTCtx):
		self.actx = actx

		self.returns : list[SExpr] = []

		self.call_casts : list[CallCast] = []
		self.type_casts: list[TypeCast] = []
		self.implicit_calls : list[SExpr] = []
		self.assigns  : list[SExpr]  = []
		self.var_reads   : list[VarUseChain]   = []

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
		for c in self.implicit_calls:
			yield c

	def iterate_assigns(self):
		for a in self.assigns:
			yield a

	def iterate_var_reads(self):
		for r in self.var_reads:
			yield r