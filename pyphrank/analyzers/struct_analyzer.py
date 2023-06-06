from __future__ import annotations

import idaapi

import pyphrank.utils as utils

from pyphrank.analyzers.type_analyzer import TypeAnalyzer
from pyphrank.containers.structure import Structure
from pyphrank.ast_parts import VarUses


class StructAnalyzer(TypeAnalyzer):
	def calculate_var_type_by_uses(self, var_uses: VarUses):
		if len(var_uses) == 0:
			return utils.UNKNOWN_TYPE

		writes = [w for w in var_uses.writes if not w.is_assign()]
		# weeding out non-pointers
		for w in writes:
			if w.target.var_use_chain is None:
				continue
			if not w.target.var_use_chain.is_possible_ptr():
				utils.log_warn("non-pointer writes are not supported for now {w}")
				return utils.UNKNOWN_TYPE

		casts = var_uses.call_casts
		# weeding out non-pointers2
		for c in casts:
			if c.arg.var_use_chain is None:
				continue
			if c.arg.var_use_chain.is_possible_ptr() is None:
				utils.log_warn(f"non-pointer casts are not supported for now {c}")
				return utils.UNKNOWN_TYPE

		reads = var_uses.reads
		# weeding out non-pointers3
		for r in reads:
			if r.var_use_chain is None:
				continue
			if not r.var_use_chain.is_possible_ptr():
				utils.log_warn(f"non-pointer reads are not supported for now {r.op}")
				return utils.UNKNOWN_TYPE

		# all cases ended, assuming new structure pointer
		lvar_struct = Structure.new()
		self.container_manager.add_struct(lvar_struct)
		lvar_tinfo = lvar_struct.ptr_tinfo
		return lvar_tinfo