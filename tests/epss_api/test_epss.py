import sys
from os.path import abspath, dirname, join, pardir

from epss_api.epss import EPSS

sys.path.append(abspath(join(dirname(__file__), pardir, pardir, "src")))

epss = EPSS()


def test_score():
    value = epss.score(cve_id='CVE-2022-0669')
    assert value == {'epss': 0.0095, 'percentile': 0.32069}
    value = epss.score(cve_id='CVE-1000-123')
    assert value is None


def test_epss():
    value = epss.epss(cve_id='CVE-2022-0669')
    assert value == 0.0095
    value = epss.epss(cve_id='CVE-1000-123')
    assert value is None


def test_percentile():
    value = epss.percentile(cve_id='CVE-2022-0669')
    assert value == 0.32069
    value = epss.percentile(cve_id='CVE-1000-123')
    assert value is None
