import unittest
from src.models import NetworkRule
from src.analyzer import assess_rule, assess

class AnalyzerTests(unittest.TestCase):
    def rule(self, **overrides):
        data=dict(provider="aws",account="test",resource="sg-1",direction="ingress",protocol="tcp",port_start=443,port_end=443,source="10.0.0.0/8",destination="10.1.0.0/24",internet_exposed=False,owner="Security",criticality="medium")
        data.update(overrides)
        return NetworkRule(**data)

    def test_invalid_provider_rejected(self):
        with self.assertRaises(ValueError): self.rule(provider="oracle")

    def test_invalid_port_range_rejected(self):
        with self.assertRaises(ValueError): self.rule(port_start=5000,port_end=80)

    def test_public_rdp_generates_finding(self):
        findings=assess_rule(self.rule(provider="azure",port_start=3389,port_end=3389,source="0.0.0.0/0",internet_exposed=True,criticality="high"))
        self.assertTrue(any("Internet-exposed" in f.title for f in findings))

    def test_internal_https_has_no_exposure_finding(self):
        self.assertEqual(assess_rule(self.rule()), [])

    def test_any_port_public_ingress_detected(self):
        findings=assess_rule(self.rule(port_start=0,port_end=65535,source="0.0.0.0/0",internet_exposed=True))
        self.assertTrue(any(f.title=="Any-protocol public ingress" for f in findings))

    def test_unrestricted_egress_detected(self):
        findings=assess_rule(self.rule(direction="egress",port_start=0,port_end=65535,destination="0.0.0.0/0"))
        self.assertTrue(any(f.title=="Unrestricted internet egress" for f in findings))

    def test_missing_owner_is_governance_finding(self):
        findings=assess_rule(self.rule(owner=""))
        self.assertTrue(any("owner" in f.title.lower() for f in findings))

    def test_score_is_bounded(self):
        findings=assess_rule(self.rule(port_start=22,port_end=22,source="0.0.0.0/0",internet_exposed=True,owner="",criticality="critical"))
        self.assertTrue(all(0 <= f.score <= 100 for f in findings))

    def test_assess_sorts_highest_risk_first(self):
        rules=[self.rule(),self.rule(resource="db",port_start=5432,port_end=5432,source="0.0.0.0/0",internet_exposed=True,criticality="critical")]
        findings=assess(rules)
        self.assertEqual(findings, sorted(findings,key=lambda f:(-f.score,f.finding_id)))

if __name__ == "__main__": unittest.main()
