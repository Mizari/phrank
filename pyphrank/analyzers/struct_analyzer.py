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

		writes_types = [self.analyze_sexpr_type(w.value) for w in writes]

		# single write at offset 0 does not create new type
		if len(var_uses) == 1 and len(writes) == 1 and writes[0].target.var_use_chain is not None and writes[0].target.var_use_chain.get_ptr_offset() == 0:
			write_type = writes_types[0].copy()
			write_type.create_ptr(write_type)
			return write_type

		# single cast at offset 0 might be existing type
		if len(casts) == 1 and casts[0].is_var_arg():
			arg_type = self.analyze_call_cast_type(casts[0])

			# casting to something unknown yield unknown
			if arg_type is utils.UNKNOWN_TYPE:
				return utils.UNKNOWN_TYPE

			# simple variable passing does not create new type
			if len(writes) == 0:
				return arg_type

			# single cast and writes into casted type
			if arg_type.is_ptr():
				arg_size = arg_type.get_pointed_object().get_size()
			else:
				arg_size = arg_type.get_size()
			if arg_size == idaapi.BADSIZE and arg_type is not utils.UNKNOWN_TYPE:
				utils.log_warn(f"failed to calculate size of argument {str(arg_type)}")
			else:
				# checking that writes do not go outside of casted value
				for i, w in enumerate(writes):
					if w.target.var_use_chain is None:
						continue
					write_start = w.target.var_use_chain.get_ptr_offset()
					if write_start is None:
						continue

					write_end = writes_types[i].get_size()
					if write_end == idaapi.BADSIZE and writes_types[i] is not utils.UNKNOWN_TYPE:
						utils.log_warn(f"failed to calculate write size of {str(writes_types[i])}")
						continue

					# found write outside of cast, new struct then
					if write_start < 0 or write_end > arg_size:
						lvar_struct = Structure.new()
						self.container_manager.add_struct(lvar_struct)
						lvar_tinfo = lvar_struct.ptr_tinfo
						return lvar_tinfo
				return arg_type

		# TODO writes into array of one type casts, that start at offset 0
		# TODO check if all writes are to the same offset
		# TODO check if all writes are actually array writes at various offsets

		# all cases ended, assuming new structure pointer
		lvar_struct = Structure.new()
		self.container_manager.add_struct(lvar_struct)
		lvar_tinfo = lvar_struct.ptr_tinfo
		return lvar_tinfo