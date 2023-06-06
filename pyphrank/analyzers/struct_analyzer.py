from __future__ import annotations

import pyphrank.utils as utils

from pyphrank.analyzers.type_analyzer import TypeAnalyzer
from pyphrank.ast_parts import VarUses


class StructAnalyzer(TypeAnalyzer):
	def is_strucptr(self, var_uses: VarUses) -> bool:
		if len(var_uses) == 0:
			return False

		writes = [w for w in var_uses.writes if not w.is_assign()]
		# weeding out non-pointers
		for w in writes:
			if w.target.var_use_chain is None:
				continue
			if not w.target.var_use_chain.is_possible_ptr():
				utils.log_warn("non-pointer writes are not supported for now {w}")
				return False

		casts = var_uses.call_casts
		# weeding out non-pointers2
		for c in casts:
			if c.arg.var_use_chain is None:
				continue
			if c.arg.var_use_chain.is_possible_ptr() is None:
				utils.log_warn(f"non-pointer casts are not supported for now {c}")
				return False

		reads = var_uses.reads
		# weeding out non-pointers3
		for r in reads:
			if r.var_use_chain is None:
				continue
			if not r.var_use_chain.is_possible_ptr():
				utils.log_warn(f"non-pointer reads are not supported for now {r.op}")
				return False

		# all cases ended, assuming new structure pointer
		return True