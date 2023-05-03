from phrank.ast_parts import *


class ASTAnalysis():
	def __init__(self, actx:ASTCtx):
		self.actx = actx

		self.returns : list[SExpr] = []
		self.call_casts : list[CallCast] = []
		self.calls : list[SExpr] = []

		self.var_writes  : list[VarWrite]  = []
		self.var_reads   : list[SExpr]   = []

	def iterate_var_writes(self, var:Var):
		for w in self.var_writes:
			if w.target.var_use_chain is None: continue
			if w.target.var_use_chain.var == var: yield w

	def iterate_var_reads(self, var:Var):
		for r in self.var_reads:
			if r.var_use_chain is None: continue
			if r.var_use_chain.var == var: yield r

	def iterate_var_call_casts(self, var:Var):
		for c in self.call_casts:
			if c.arg.var_use_chain is None: continue
			if c.arg.var_use_chain.var == var: yield c

	def get_var_uses(self, var:Var) -> VarUses:
		var_uses = VarUses()
		var_uses.writes = [w for w in self.iterate_var_writes(var)]
		var_uses.reads = [r for r in self.iterate_var_reads(var)]
		var_uses.casts = [c for c in self.iterate_var_call_casts(var)]
		return var_uses