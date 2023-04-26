from __future__ import annotations

import idaapi

from phrank.ast_parts import *


class ASTAnalysis():
	def __init__(self, actx:ASTCtx):
		self.actx = actx

		self.returns : list[ReturnWrapper] = []
		self.call_casts : list[CallCast] = []
		self.calls : list[FuncCall] = []

		self.var_writes  : list[VarWrite]  = []
		self.var_reads   : list[VarRead]   = []

	def iterate_lvar_writes(self, func_ea:int, lvar_id:int):
		for w in self.var_writes:
			if not w.var.is_lvar(func_ea, lvar_id): continue
			yield w

	def iterate_gvar_writes(self, gvar_id:int):
		for w in self.var_writes:
			if not w.var.is_gvar(gvar_id): continue
			yield w

	def iterate_lvar_reads(self, func_ea:int, lvar_id:int):
		for r in self.var_reads:
			if not r.var.is_lvar(func_ea, lvar_id): continue
			yield r

	def iterate_gvar_reads(self, gvar_id:int):
		for r in self.var_reads:
			if not r.var.is_gvar(gvar_id): continue
			yield r

	def iterate_lvar_call_casts(self, func_ea:int, lvar_id:int):
		for c in self.call_casts:
			if not c.var.is_lvar(func_ea, lvar_id):
				continue
			yield c

	def iterate_gvar_call_casts(self, gvar_id:int):
		for c in self.call_casts:
			if not c.var.is_gvar(gvar_id):
				continue
			yield c