from pyphrank.ast_parts import SExpr, ASTCtx, Var, VarUseChain, Node


def extract_implicit_calls(sexpr:SExpr):
	if sexpr.is_implicit_call():
		yield sexpr


def extract_var_reads(sexpr:SExpr):
	if sexpr.is_var_use_chain():
		yield sexpr.var_use_chain

	if sexpr.is_assign():
		# dont add target var_use_chain to reads, because it is write
		# if its not var_use_chain, then it gets added to reads there
		if not sexpr.target.is_var_use_chain():
			yield from extract_var_reads(sexpr.target)

		# var_use_chain value IS a read though
		yield from extract_var_reads(sexpr.value)

	if sexpr.is_binary_op():
		yield from extract_var_reads(sexpr.x)
		yield from extract_var_reads(sexpr.y)

	if sexpr.is_bool_op():
		yield from extract_var_reads(sexpr.x)
		yield from extract_var_reads(sexpr.y)


class ASTAnalysis():
	def __init__(self, entry:Node, actx:ASTCtx):
		self.actx = actx
		self.entry = entry

	def print_graph(self):
		print("graph size =", len([n for n in self.iterate_nodes()]))
		self.print_node(self.entry, 0)

	def print_node(self, node:Node, lvl):
		print(f"{'  ' * lvl}{node}")
		for c in node.children:
			self.print_node(c, lvl + 1)

	def iterate_nodes(self, start=None):
		if start is None:
			start = self.entry
		yield start
		for child in start.children:
			yield from self.iterate_nodes(child)

	def iterate_sexprs(self):
		for node in self.iterate_nodes():
			if node.is_expr():
				yield node.sexpr

	def iterate_returns(self):
		for node in self.iterate_nodes():
			if node.is_return():
				yield node.sexpr

	def iterate_call_casts(self):
		for node in self.iterate_nodes():
			if node.is_call_cast():
				yield node

	def iterate_type_casts(self):
		for node in self.iterate_nodes():
			if node.is_type_cast():
				yield node

	def iterate_implicit_calls(self):
		for c in self.iterate_sexprs():
			yield from extract_implicit_calls(c)

		for r in self.iterate_returns():
			yield from extract_implicit_calls(r)

		for c in self.iterate_call_casts():
			yield from extract_implicit_calls(c.sexpr)

		for t in self.iterate_type_casts():
			yield from extract_implicit_calls(t.sexpr)

	def iterate_assigns(self):
		for sexpr in self.iterate_sexprs():
			if sexpr.is_assign():
				yield sexpr

	def iterate_var_reads(self):
		for s in self.iterate_sexprs():
			yield from extract_var_reads(s)

		for r in self.iterate_returns():
			yield from extract_var_reads(r)

		for c in self.iterate_call_casts():
			# direct var use chain casts are casts, not reads
			if not c.sexpr.is_var_use_chain():
				yield from extract_var_reads(c.sexpr)

		for t in self.iterate_type_casts():
			# direct var use chain casts are casts, not reads
			if not t.sexpr.is_var_use_chain():
				yield from extract_var_reads(t.sexpr)