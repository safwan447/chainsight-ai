import networkx as nx
def build_graph(incident, events, detections):
    graph=nx.MultiDiGraph(); by_id={e.event_id:e for e in events}; ids={d.event_id for d in detections} or {e.event_id for e in events}
    graph.add_node(incident.incident_id,type="incident",label=incident.incident_id)
    for event_id in ids:
        e=by_id.get(event_id)
        if not e: continue
        entities=[("host",e.host),("user",e.user),("ip",e.source_ip),("ip",e.destination_ip),("process",e.process_name),("domain",e.domain)]
        prior=incident.incident_id
        for kind,value in entities:
            if not value: continue
            node=f"{kind}:{value}"; graph.add_node(node,type=kind,label=value); graph.add_edge(prior,node,relationship="observed in event",timestamp=e.timestamp.isoformat(),event_ids=[e.event_id],confidence=.9,inferred=False); prior=node
    return {"nodes":[{"id":n,**data} for n,data in graph.nodes(data=True)],"edges":[{"id":f"{a}-{b}-{i}","source":a,"target":b,**data} for a,b,i,data in graph.edges(keys=True,data=True)]}
def reachability(graph_data,start=None):
    nodes={n["id"]:n for n in graph_data["nodes"]}; edges=graph_data["edges"]; starts=[start] if start else [n["id"] for n in graph_data["nodes"] if n.get("type")=="host"]
    result=[]
    for edge in edges:
        if edge["source"] in starts and edge["target"] not in starts: result.append({"starting_entity":edge["source"],"potential_entity":edge["target"],"relationship":edge["relationship"],"supporting_event_ids":edge["event_ids"],"confidence":edge["confidence"],"reason":"Observed relationship; reachability is a defensive lead, not compromise evidence."})
    return result
