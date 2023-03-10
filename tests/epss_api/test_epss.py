import sys
from os.path import abspath, dirname, join, pardir
import pytest

from epss_api.epss import EPSS, Score

sys.path.append(abspath(join(dirname(__file__), pardir, pardir, "src")))

epss = EPSS()


def test_scores():
    value = epss.scores()
    assert len(value) >= 1000
    assert value[0].cve.startswith('CVE-')
    assert 0 <= value[0].epss <= 1
    assert 0 <= value[0].percentile <= 1


def test_csv():
    rows = epss.csv()
    assert rows[0].startswith('#model_version')
    assert rows[1] == 'cve,epss,percentile'
    assert len(rows[2:]) >= 1000


@pytest.mark.parametrize("max", [-1, 0, 0.5, 1, 2])
def test_epss_gt(max):
    value = epss.epss_gt(max)
    for s in value:
        assert s.epss >= max


@pytest.mark.parametrize("max", [-1, 0, 0.5, 1, 2])
def test_percentile_gt(max):
    value = epss.percentile_gt(max)
    for s in value:
        assert s.percentile >= max


@pytest.mark.parametrize("min", [-1, 0, 0.5, 1, 2])
def test_epss_lt(min):
    value = epss.epss_lt(min)
    for s in value:
        assert s.epss <= min


@pytest.mark.parametrize("min", [-1, 0, 0.5, 1, 2])
def test_percentile_lt(min):
    value = epss.percentile_lt(min)
    for s in value:
        assert s.percentile <= min


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


def test_score_dict():
    score = Score(cve='CVE-2022-39952',
                  epss='0.09029',
                  percentile='0.94031')
    dict_score = score.__dict__
    assert 'cve' in dict_score.keys()
    assert 'epss' in dict_score.keys()
    assert 'percentile' in dict_score.keys()
