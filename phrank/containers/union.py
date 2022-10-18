from phrank.containers.ida_struc_wrapper import IdaStrucWrapper

class Union(IdaStrucWrapper):
	def __init__(self, struc_locator=None):
		super().__init__(struc_locator=struc_locator, is_union=True)
		assert not self.is_union(), "Error, should be union"