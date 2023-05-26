import idc
import idaapi

from pyphrank.containers.ida_struc_wrapper import IdaStrucWrapper

class Union(IdaStrucWrapper):
	def __init__(self, strucid):
		super().__init__(strucid)
		assert not self.is_union(), "Error, should be union"

	@classmethod
	def create(cls, struc_name=None):
		strucid = idc.add_struc(idaapi.BADADDR, struc_name, True)
		return cls(strucid)