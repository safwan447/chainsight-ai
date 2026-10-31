from backend.graph.attack_graph import build_graph, reachability
from backend.models import Incident
from tests.test_detection import make

def test_graph_contains_observed_host_edge():
    e=make();e.host="WS-01"; i=Incident(incident_id="INC-1",first_observed=e.timestamp,last_observed=e.timestamp,event_count=1,detection_count=1,severity="high",confidence=.8)
    graph=build_graph(i,[e],[])
    assert any(n["type"]=="host" for n in graph["nodes"])
    assert all(not edge["inferred"] for edge in graph["edges"])
