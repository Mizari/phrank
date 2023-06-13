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

	def get_var_uses(self, var:Var) -> VarUses:
		var_uses = VarUses()
		for w in self.var_assigns:
			if w.target.is_var(var):
				var_uses.moves_to.append(w.value)
			elif w.target.is_var_use(var):
				var_uses.writes.append(w)
			if w.value.is_var(var):
				var_uses.moves_from.append(w.target)

		var_uses.reads = [r for r in self.var_reads if r.is_var_use(var)]
		var_uses.call_casts = [c for c in self.call_casts if c.arg.is_var_use(var)]
		var_uses.type_casts = [c for c in self.type_casts if c.arg.is_var_use(var)]
		return var_uses