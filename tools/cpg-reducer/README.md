`cpg-reducer` is a utility that reduces a compartment policy graph.

The input CPG can be reduced by merging intra-compartment nodes to replace them
with a single node representing a compartment (currently a compilation unit --
an object file of a source code file).

The output consists of the reduced CPG consisting of nodes and edges with their
lables and is specific to selected visualisation utilities (currently D3).
