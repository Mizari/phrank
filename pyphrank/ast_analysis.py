from __future__ import annotations

import idaapi

from pyphrank.ast_parts import SExpr, ASTCtx, Var, VarUseChain, Node


def extract_implicit_calls(sexpr:SExpr):
	if sexpr.is_implicit_call():
		yield sexpr


def extract_var_reads(sexpr:SExpr):
	if sexpr.is_var_use_chain():
		yield sexpr

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


class VarWrite:
	def __init__(self, target:VarUseChain, value:SExpr) -> None:
		self.target = target
		self.value = value


def is_assign_write(asg:SExpr) -> bool:
	if asg.target.is_var():
		return False
	return asg.target.is_var_use()


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
				new_child.parents.add(new_node)
				new_node.children.add(new_child)

		new_entry = node2new[self.entry]
		return ASTAnalysis(new_entry, self.actx)

	def print_graph(self, graph_title:str):
		gv = ASTAnalysisGraphView(graph_title)
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

	def iterate_sexpr_nodes(self):
		for node in self.iterate_nodes():
			if node.is_expr():
				yield node

	def iterate_sexprs(self):
		for node in self.iterate_sexpr_nodes():
			yield node.sexpr

	def iterate_return_nodes(self):
		for node in self.iterate_nodes():
			if node.is_return():
				yield node

	def iterate_return_sexprs(self):
		for node in self.iterate_return_nodes():
			yield node.sexpr

	def iterate_call_cast_nodes(self):
		for node in self.iterate_nodes():
			if node.is_call_cast():
				yield node

	def iterate_call_cast_sexprs(self):
		for node in self.iterate_call_cast_nodes():
			yield node.sexpr

	def iterate_type_cast_nodes(self):
		for node in self.iterate_nodes():
			if node.is_type_cast():
				yield node

	def iterate_type_cast_sexprs(self):
		for node in self.iterate_type_cast_nodes():
			yield node.sexpr

	def iterate_implicit_calls(self):
		for c in self.iterate_sexprs():
			yield from extract_implicit_calls(c)

		for r in self.iterate_return_sexprs():
			yield from extract_implicit_calls(r)

		for c in self.iterate_call_cast_sexprs():
			yield from extract_implicit_calls(c)

		for t in self.iterate_type_cast_sexprs():
			yield from extract_implicit_calls(t)

	def iterate_assign_nodes(self):
		for node in self.iterate_sexpr_nodes():
			if node.sexpr.is_assign():
				yield node

	def iterate_assign_sexprs(self):
		for node in self.iterate_assign_nodes():
			yield node.sexpr

	def iterate_var_reads(self):
		for s in self.iterate_sexprs():
			yield from extract_var_reads(s)

		for r in self.iterate_return_sexprs():
			yield from extract_var_reads(r)

		for c in self.iterate_call_cast_sexprs():
			# direct var use chain casts are casts, not reads
			if not c.is_var_use_chain():
				yield from extract_var_reads(c)

		for t in self.iterate_type_cast_sexprs():
			# direct var use chain casts are casts, not reads
			if not t.is_var_use_chain():
				yield from extract_var_reads(t)



	def casts_len(self):
		casts1 = [c for c in self.iterate_call_cast_sexprs()]
		casts2 = [c for c in self.iterate_type_cast_sexprs()]
		return len(casts1) + len(casts2)

	def uses_len(self):
		writes = [w for w in self.iterate_writes()]
		reads = [r for r in self.iterate_var_reads()]
		return len(writes) + len(reads) + self.casts_len()

	def total_len(self):
		moves_to = [m for m in self.iterate_moves_to()]
		moves_from = [m for m in self.iterate_moves_from()]
		return self.uses_len() + len(moves_to) + len(moves_from)

	def iterate_moves_to(self):
		for asg in self.iterate_assign_sexprs():
			if asg.target.is_var():
				yield asg.value

	def iterate_moves_from(self):
		for asg in self.iterate_assign_sexprs():
			if asg.value.is_var():
				yield asg.target

	def iterate_writes(self):
		for asg in self.iterate_assign_sexprs():
			if is_assign_write(asg):
				yield VarWrite(asg.target.var_use_chain, asg.value)