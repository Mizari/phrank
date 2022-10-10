


class TypeAnalyzer:
	def __init__(self) -> None:
		self.type2func = {}
		self.type2reads = {}
		self.type2writes = {}

		self.lvar2type = {}
		self.gvar2type = {}
		self.field2type = {}
		self.retval2type = {}

		self.new_types = []
		self.new_xrefs = []
		self.new_lvars = []
		self.new_gvars = []
		self.new_fields = []
		self.new_retvals = []