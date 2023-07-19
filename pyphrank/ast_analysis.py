from __future__ import annotations

import idaapi

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


class ASTAnalysisGraphView(idaapi.GraphViewer):
	def __init__(self, name:str):
		super().__init__(name)

	def OnRefresh(self):
		return True

	def OnGetText(self, node_id):
		return self[node_id]


class ASTAnalysis:
	def __init__(self, entry:Node, actx:ASTCtx):
		self.actx = actx
		self.entry = entry

	def copy(self) -> ASTAnalysis:
		node2new : dict[Node,Node] = {}
		for node in self.iterate_nodes():
			new_node = node.copy()
			node2new[node] = new_node

		for node in self.iterate_nodes():
			new_node = node2new[node]
			for child in node.children:
				new_child = node2new[child]
				new_child.parents.append(new_node)
				new_node.children.append(new_child)

		new_entry = node2new[self.entry]
		return ASTAnalysis(new_entry, self.actx)

	def print_graph(self):
		gv = ASTAnalysisGraphView(f"{idaapi.get_name(self.actx.addr)} ASTAnalysis")
		node2id = {}
		for node in self.iterate_nodes():
			node2id[node] = gv.AddNode(str(node))

		for node in self.iterate_nodes():
			child_id = node2id[node]
			for parent in node.parents:
				parent_id = node2id[parent]
				gv.AddEdge(parent_id, child_id)

		gv.Show()

	def iterate_nodes(self):
		yield self.entry
		yield from self.entry.iterate_children()

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