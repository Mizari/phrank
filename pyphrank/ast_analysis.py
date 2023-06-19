from pyphrank.ast_parts import SExpr, ASTCtx, CallCast, TypeCast, VarWrite, Var, VarUses, Assign, VarUseChain


class ASTAnalysis():
	def __init__(self, actx:ASTCtx):
		self.actx = actx

		self.returns : list[SExpr] = []
		self.call_casts : list[CallCast] = []
		self.type_casts: list[TypeCast] = []
		self.calls : list[SExpr] = []

		self.assigns  : list[Assign]  = []
		self.var_reads   : list[VarUseChain]   = []

	def get_var_uses(self, var:Var) -> VarUses:
		var_uses = VarUses()
		for asg in self.assigns:
			if asg.target.is_var(var):
				var_uses.moves_to.append(asg.value)
			elif asg.target.is_var_use(var):
				write = VarWrite(asg.target.var_use_chain, asg.value)
				var_uses.writes.append(write)
			if asg.value.is_var(var):
				var_uses.moves_from.append(asg.target)

		var_uses.reads = [r for r in self.var_reads if r.var == var]
		var_uses.call_casts = [c for c in self.call_casts if c.arg.is_var_use(var)]
		var_uses.type_casts = [c for c in self.type_casts if c.arg.is_var_use(var)]
		return var_uses