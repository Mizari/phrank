from pyphrank.ast_parts import SExpr, ASTCtx, CallCast, TypeCast, VarWrite, Var, VarUses


class ASTAnalysis():
	def __init__(self, actx:ASTCtx):
		self.actx = actx

		self.returns : list[SExpr] = []
		self.call_casts : list[CallCast] = []
		self.type_casts: list[TypeCast] = []
		self.calls : list[SExpr] = []

		self.var_assigns  : list[VarWrite]  = []
		self.var_reads   : list[SExpr]   = []

	def iterate_var_assigns(self, var:Var):
		for w in self.var_assigns:
			if w.target.is_var_use(var):
				yield w

	def iterate_var_reads(self, var:Var):
		for r in self.var_reads:
			if r.is_var_use(var):
				yield r

	def iterate_var_call_casts(self, var:Var):
		for c in self.call_casts:
			if c.arg.is_var_use(var):
				yield c

	def iterate_var_type_casts(self, var:Var):
		for c in self.type_casts:
			if c.arg.is_var_use(var):
				yield c

	def get_var_uses(self, var:Var) -> VarUses:
		var_uses = VarUses()
		var_uses.writes = [w for w in self.iterate_var_assigns(var)]
		var_uses.reads = [r for r in self.iterate_var_reads(var)]
		var_uses.call_casts = [c for c in self.iterate_var_call_casts(var)]
		var_uses.type_casts = [c for c in self.iterate_var_type_casts(var)]
		return var_uses