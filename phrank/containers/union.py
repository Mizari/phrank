import idaapi
from phrank.containers.ida_struc_wrapper import IdaStrucWrapper

class Union(IdaStrucWrapper):
	def __init__(self, *args, **kwargs):
		super().__init__(is_union=True, *args, **kwargs)
		if not idaapi.is_union(self.strucid):
			raise BaseException("Error, should be union " + self.get_name())

	@staticmethod
	def is_union():
		# TODO
		return