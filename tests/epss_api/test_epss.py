import sys
from os.path import abspath, dirname, join, pardir

from epss_api.epss import EPSS

sys.path.append(abspath(join(dirname(__file__), pardir, pardir, "src")))

epss = EPSS()


def test_score():
    score = epss.score(cve_id='CVE-2022-0669')
    assert score == {'epss': 0.0095, 'percentile': 0.32069}


def test_epss():
    value = epss.epss(cve_id='CVE-2022-0669')
    assert value == 0.0095


def test_percentile():
    value = epss.percentile(cve_id='CVE-2022-0669')
    assert value == 0.32069
