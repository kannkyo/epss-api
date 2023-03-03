import sys
from os.path import abspath, dirname, join, pardir

from epss_api.epss import EPSS

sys.path.append(abspath(join(dirname(__file__), pardir, pardir, "src")))

epss = EPSS()


def test_scores():
    value = epss.scores()
    assert len(value) >= 1000
    assert value[0].cve.startswith('CVE-')
    assert 0 <= value[0].epss <= 1
    assert 0 <= value[0].percentile <= 1


def test_score():
    value = epss.score(cve_id='CVE-2022-0669')
    assert value.cve.startswith('CVE-')
    assert 0 <= value.epss <= 1
    assert 0 <= value.percentile <= 1
    value = epss.score(cve_id='CVE-1000-123')
    assert value is None


def test_epss():
    value = epss.epss(cve_id='CVE-2022-0669')
    assert 0 <= value <= 1
    value = epss.epss(cve_id='CVE-1000-123')
    assert value is None


def test_percentile():
    value = epss.percentile(cve_id='CVE-2022-0669')
    assert 0 <= value <= 1
    value = epss.percentile(cve_id='CVE-1000-123')
    assert value is None
