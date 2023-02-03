from __future__ import annotations

import idaapi

from phrank.ast_parts import *


class ASTAnalysis():
	def __init__(self, actx:ASTCtx):
		self.actx = actx

		self.returns : list[ReturnWrapper] = []
		self.call_casts : list[CallCast] = []

		self.var_assigns : list[VarAssign] = []
		self.var_writes  : list[VarWrite]  = []
		self.lvar_reads   : list[VarRead]   = []

		self.unknown_casts = []
		self.unknown_asgs = []

	def iterate_lvar_assigns(self, func_ea:int, lvar_id:int):
		for a in self.var_assigns:
			if not a.var.is_lvar(func_ea, lvar_id): continue
			yield a

	def iterate_gvar_assigns(self, gvar_id:int):
		for a in self.var_assigns:
			if not a.var.is_gvar(gvar_id): continue
			yield a

	def iterate_lvar_writes(self, func_ea:int, lvar_id:int):
		for w in self.var_writes:
			if not w.var.is_lvar(func_ea, lvar_id): continue
			yield w

	def iterate_gvar_writes(self, gvar_id:int):
		for w in self.var_writes:
			if not w.var.is_gvar(gvar_id): continue
			yield w

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