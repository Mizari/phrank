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