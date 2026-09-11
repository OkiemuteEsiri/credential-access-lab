import json, tempfile, unittest
from pathlib import Path
from src.models import Event, Identity
from src.detector import assess, metrics
from src.ingestion import load_events, load_identities
from src.reporting import render
from src.remediation import validate_closure

class CredentialAccessTests(unittest.TestCase):
    def event(self, **kw):
        base=dict(event_id="e1",host="H1",user="u1",process="x.exe",action="process_access",target="lsass.exe",approved_admin_tool=False,access_succeeded=True,edr_healthy=True,asset_criticality="high")
        base.update(kw); return Event(**base)

    def test_lsass_detection(self):
        f=assess([self.event()],{"u1":Identity("u1",False,True)})[0]
        self.assertEqual(f.technique,"T1003.001")

    def test_privileged_increases_score(self):
        normal=assess([self.event()],{"u1":Identity("u1",False,True)})[0].score
        privileged=assess([self.event()],{"u1":Identity("u1",True,True)})[0].score
        self.assertGreater(privileged,normal)

    def test_approved_tool_reduces_score(self):
        a=assess([self.event(approved_admin_tool=False)],{})[0].score
        b=assess([self.event(approved_admin_tool=True)],{})[0].score
        self.assertLess(b,a)

    def test_score_bounded(self):
        f=assess([self.event(asset_criticality="critical",edr_healthy=False)],{"u1":Identity("u1",True,True)})[0]
        self.assertLessEqual(f.score,100)

    def test_deterministic_id(self):
        a=assess([self.event()],{})[0].finding_id; b=assess([self.event()],{})[0].finding_id
        self.assertEqual(a,b)

    def test_sorting(self):
        rows=[self.event(event_id="a",asset_criticality="low",access_succeeded=False),self.event(event_id="b",asset_criticality="critical",edr_healthy=False)]
        out=assess(rows,{})
        self.assertGreaterEqual(out[0].score,out[1].score)

    def test_metrics(self):
        out=assess([self.event()],{})
        self.assertEqual(metrics(out)["total"],1)

    def test_report_contains_attack(self):
        self.assertIn("T1003.001",render(assess([self.event()],{})))

    def test_unmatched_event_not_flagged(self):
        self.assertEqual(assess([self.event(action="file_read",target="config")],{}),[])

    def test_duplicate_event_rejected(self):
        row={"event_id":"x","host":"h","user":"u","process":"p","action":"process_access","target":"lsass.exe","approved_admin_tool":False,"access_succeeded":True,"edr_healthy":True,"asset_criticality":"high"}
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"x.json"; p.write_text(json.dumps([row,row]))
            with self.assertRaises(ValueError): load_events(p)

    def test_bad_boolean_rejected(self):
        row={"event_id":"x","host":"h","user":"u","process":"p","action":"process_access","target":"lsass.exe","approved_admin_tool":"false","access_succeeded":True,"edr_healthy":True,"asset_criticality":"high"}
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"x.json"; p.write_text(json.dumps([row]))
            with self.assertRaises(ValueError): load_events(p)

    def test_duplicate_identity_rejected(self):
        rows=[{"user":"u","privileged":False,"enabled":True},{"user":"u","privileged":True,"enabled":True}]
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"i.json"; p.write_text(json.dumps(rows))
            with self.assertRaises(ValueError): load_identities(p)

    def test_valid_closure(self):
        r={"finding_id":"CA-X","owner":"sec","change_reference":"CHG-1","remediation_action":"removed unauthorized access","endpoint_validated":True,"identity_reviewed":True,"detection_retested":True,"validation_passed":True}
        self.assertEqual(validate_closure(r)[0],"validated")

    def test_incomplete_closure(self):
        r={"finding_id":"CA-X","owner":"sec","change_reference":"CHG-1","remediation_action":"fixed","endpoint_validated":True,"identity_reviewed":False,"detection_retested":True,"validation_passed":True}
        self.assertEqual(validate_closure(r)[0],"needs_evidence")

if __name__ == "__main__": unittest.main()
