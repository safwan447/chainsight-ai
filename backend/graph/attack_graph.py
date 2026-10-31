from __future__ import annotations

from typing import Any
import networkx as nx
from backend.models import Detection, Incident, NormalizedEvent


def _node(kind: str, value: str) -> str:
    return f"{kind}:{value}"


def build_graph(
    incident: Incident,
    events: list[NormalizedEvent],
    detections: list[Detection],
) -> dict[str, list[dict[str, Any]]]:
    """Create a deterministic graph of observed entities and relationships.

    Observed edges are directly backed by recorded telemetry. Inferred edges represent
    hypothetical attack paths and are clearly marked with inferred=True.
    """
    graph = nx.MultiDiGraph()
    inc_node = _node("incident", incident.incident_id)
    graph.add_node(
        inc_node,
        type="incident",
        label=incident.incident_id,
        risk_label=incident.risk_label,
        risk_score=incident.risk_score,
    )

    evidence_ids = {d.event_id for d in detections} or {e.event_id for e in events}
    edge_index: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add(
        kind_a: str,
        value_a: str | None,
        kind_b: str,
        value_b: str | None,
        relationship: str,
        event: NormalizedEvent,
        confidence: float = 0.9,
        inferred: bool = False,
    ) -> None:
        if not value_a or not value_b:
            return
        source = _node(kind_a, value_a)
        target = _node(kind_b, value_b)
        graph.add_node(source, type=kind_a, label=value_a)
        graph.add_node(target, type=kind_b, label=value_b)

        key = (source, target, relationship)
        if key in edge_index:
            if event.event_id not in edge_index[key]["event_ids"]:
                edge_index[key]["event_ids"].append(event.event_id)
            return

        data: dict[str, Any] = {
            "relationship": relationship,
            "timestamp": event.timestamp.isoformat(),
            "event_ids": [event.event_id],
            "confidence": confidence,
            "inferred": inferred,
        }
        graph.add_edge(source, target, **data)
        edge_index[key] = data

    for event in events:
        if event.event_id not in evidence_ids:
            continue

        # Link evidence entities to incident
        for kind, value in [
            ("host", event.host),
            ("user", event.user),
            ("ip", event.source_ip),
            ("ip", event.destination_ip),
            ("process", event.process_name),
            ("domain", event.domain),
        ]:
            if value:
                add("incident", incident.incident_id, kind, value, "evidence associated with incident", event)

        # Entity-to-entity direct observations
        add("host", event.host, "user", event.user, "user activity observed on host", event)
        add("host", event.host, "ip", event.source_ip, "host observed using source IP", event)
        add("host", event.host, "process", event.process_name, "process observed on host", event)
        add("process", event.parent_process, "process", event.process_name, "parent process observed spawning process", event)
        add("ip", event.source_ip, "ip", event.destination_ip, "network connection observed", event)
        add("ip", event.source_ip, "domain", event.domain, "source IP observed querying or connecting to domain", event)
        add("process", event.process_name, "domain", event.domain, "process associated with domain activity", event)

    nodes = [{"id": node, **data} for node, data in graph.nodes(data=True)]
    edges = [
        {"id": f"{source}-{target}-{index}", "source": source, "target": target, **data}
        for source, target, index, data in graph.edges(keys=True, data=True)
    ]
    return {"nodes": nodes, "edges": edges}


def reachability(graph_data: dict[str, list[dict[str, Any]]], start: str | None = None) -> list[dict[str, Any]]:
    """Return observed source-IP to destination-IP chains as defensive investigation leads.

    Labels every lead clearly as potential, not confirmed compromise.
    """
    edges = graph_data.get("edges", [])
    starts = [start] if start else [node["id"] for node in graph_data.get("nodes", []) if node.get("type") == "host"]
    links: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        links.setdefault(edge["source"], []).append(edge)

    output = []
    seen = set()
    for host in starts:
        for host_ip in links.get(host, []):
            if host_ip.get("relationship") != "host observed using source IP":
                continue
            for connection in links.get(host_ip.get("target", ""), []):
                if connection.get("relationship") != "network connection observed":
                    continue
                key = (host, connection.get("target"))
                if key in seen:
                    continue
                seen.add(key)
                output.append({
                    "starting_entity": host,
                    "potential_entity": connection.get("target"),
                    "relationship": "observed source-IP to destination-IP connection",
                    "supporting_event_ids": sorted(set(host_ip.get("event_ids", []) + connection.get("event_ids", []))),
                    "confidence": min(float(host_ip.get("confidence", 0.8)), float(connection.get("confidence", 0.8))),
                    "reason": "Observed connectivity is a defensive investigation lead only; it does not confirm access or compromise.",
                })
    return output
