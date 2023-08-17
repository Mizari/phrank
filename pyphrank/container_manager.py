from __future__ import annotations

import idc
import idaapi

from pyphrank.containers.structure import Structure

import pyphrank.utils as utils


class ContainerManager:
	def __init__(self) -> None:
		self.new_types : dict[int, Structure] = {}

	def delete_containers(self):
		for t in self.new_types:
			idc.del_struc(t)
		self.new_types.clear()

	def clear(self):
		self.new_types.clear()

	def add_struct(self, struc:Structure):
		self.new_types[struc.strucid] = struc

	def get_struct(self, strucid:int) -> Structure|None:
		return self.new_types.get(strucid)

	def add_member_name(self, strucid:int, offset:int, name:str):
		# rogue shifted struct
		if offset < 0:
			return

		# do not modificate existing types
		lvar_struct = self.new_types.get(strucid)
		if lvar_struct is None:
			return

		# use of the member exists, thus there should be the field
		if not lvar_struct.member_exists(offset):
			lvar_struct.add_member(offset)

		lvar_struct.set_member_name(offset, name)

	def add_member_type(self, strucid:int, offset:int, member_type:idaapi.tinfo_t):
		# rogue shifted struct
		if offset < 0:
			return

		# do not modificate existing types
		lvar_struct = self.new_types.get(strucid)
		if lvar_struct is None:
			return

		# use of the member exists, thus there should be the field
		if not lvar_struct.member_exists(offset):
			if not lvar_struct.add_member(offset):
				return

		# if unknown, then simply creating new member is enough
		if member_type is utils.UNKNOWN_TYPE:
			return

		next_offset = lvar_struct.get_next_member_offset(offset)
		if next_offset != -1 and offset + member_type.get_size() > next_offset:
			# TODO remove when struct sizes are remembered
			# currently struct size is set by adding 1byte int at the end
			# if that is the case, then allow member type setting
			if lvar_struct.get_member_size(next_offset) != 1 or lvar_struct.size != next_offset + 1:
				utils.log_warn(
					f"failed to change type of "\
					f"{lvar_struct.name} at {hex(offset)} "\
					f"to {str(member_type)} "\
					f"because it overwrites next field at "\
					f"{hex(next_offset)} skipping member type change"
				)
				return

		member_offset = lvar_struct.get_member_start(offset)
		current_type = lvar_struct.get_member_type(offset)
		if  current_type is not None and \
			current_type.is_struct() and \
			current_type.get_size() > member_type.get_size():

			strucid = utils.tif2strucid(current_type)
			self.add_member_type(strucid, offset - member_offset, member_type)
		else:
			lvar_struct.set_member_type(offset, member_type)