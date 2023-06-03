import idaapi
import pyphrank.utils as utils

from pyphrank.analyzers.type_analyzer import TypeAnalyzer
from pyphrank.ast_parts import Var
from pyphrank.containers.vtable import Vtable


class VtableAnalyzer(TypeAnalyzer):
	def analyze_var(self, var:Var) -> idaapi.tinfo_t:
		if var.is_local():
			return utils.UNKNOWN_TYPE

		vtbl = self.var2tinfo.get(var)
		if vtbl is not None:
			return vtbl

		# trying to initialize from type at address
		if (vtbl := Vtable.get_vtable_at_address(var.obj_ea)) is not None:
			tif = vtbl.tinfo
		elif (vtbl := Vtable.from_data(var.obj_ea)) is not None:
			tif = vtbl.tinfo
			self.new_types.add(vtbl.strucid)
		else:
			tif = utils.UNKNOWN_TYPE

		self.var2tinfo[var] = tif
		return tif