import networkx as nx
import pydot

bb = [
    {
        "dst": 8477, 
        "src": 8448, 
        "type": "CONDITIONAL_JUMP"
    }, 
    {
        "dst": 8457, 
        "src": 8448, 
        "type": "FALL_THROUGH"
    }, 
    {
        "dst": 8464, 
        "src": 8457, 
        "type": "FALL_THROUGH"
    }, 
    {
        "dst": 8464, 
        "src": 8464, 
        "type": "CONDITIONAL_JUMP"
    }, 
    {
        "dst": 8476, 
        "src": 8464, 
        "type": "FALL_THROUGH"
    }
]

Graph = nx.DiGraph()

for node in bb:
    Graph.add_edge(hex(node['src']), hex(node['dst']))
    if node['type'] == "CONDITIONAL_JUMP":
        Graph.edges[hex(node['src']), hex(node['dst'])]['color'] = "blue"
    elif node['type'] == "UNCONDITIONAL_JUMP":
        Graph.edges[hex(node['src']), hex(node['dst'])]['color'] = "green"

dot_data = nx.nx_pydot.to_pydot(Graph)
svg = pydot.graph_from_dot_data(dot_data.to_string())[0].create_svg()
svg_path = "test.svg"
f = open(svg_path, 'w')
f.write(svg.decode())
f.close()