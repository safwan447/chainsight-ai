SEVERITY={"informational":0,"low":10,"medium":25,"high":45,"critical":65}
def score(incident,detections):
    highest=max((SEVERITY.get(d.severity,0) for d in detections),default=0); tactics=len({d.tactic for d in detections}); volume=min(15,max(0,(len(detections)-1)*3)); breadth=min(10,max(0,(tactics-1)*5)); confidence=round(sum(d.confidence for d in detections)/max(1,len(detections))*10)
    value=min(100,round(highest+volume+breadth+confidence)); label="Critical" if value>=80 else "High" if value>=55 else "Medium" if value>=25 else "Low"
    return value,label,[f"highest detection severity contributes {highest}",f"{len(detections)} detection(s) contribute {volume}",f"{tactics} tactic(s) contribute {breadth}",f"average evidence confidence contributes {confidence}"]
