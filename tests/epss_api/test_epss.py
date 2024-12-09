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


@pytest.mark.parametrize("min", [-1, 0, 0.5, 1, 2])
def test_epss_gt(min):
    scores = epss.epss_gt(min)
    for s in scores:
        assert s.epss > min
    for s in list(set(scores) - set(epss.scores())):
        assert s.epss <= min


@pytest.mark.parametrize("min", [-1, 0, 0.5, 1, 2])
def test_percentile_gt(min):
    scores = epss.percentile_gt(min)
    for s in scores:
        assert s.percentile > min
    for s in list(set(scores) - set(epss.scores())):
        assert s.percentile <= min


@pytest.mark.parametrize("min", [-1, 0, 0.5, 1, 2])
def test_epss_ge(min):
    scores = epss.epss_ge(min)
    for s in scores:
        assert s.epss >= min
    for s in list(set(scores) - set(epss.scores())):
        assert s.epss < min


@pytest.mark.parametrize("min", [-1, 0, 0.5, 1, 2])
def test_percentile_ge(min):
    scores = epss.percentile_ge(min)
    for s in scores:
        assert s.percentile >= min
    for s in list(set(scores) - set(epss.scores())):
        assert s.percentile < min


@pytest.mark.parametrize("max", [-1, 0, 0.5, 1, 2])
def test_epss_lt(max):
    scores = epss.epss_lt(max)
    for s in scores:
        assert s.epss < max
    for s in list(set(scores) - set(epss.scores())):
        assert s.epss >= max


@pytest.mark.parametrize("max", [-1, 0, 0.5, 1, 2])
def test_percentile_lt(max):
    scores = epss.percentile_lt(max)
    for s in scores:
        assert s.percentile < max
    for s in list(set(scores) - set(epss.scores())):
        assert s.percentile >= max


@pytest.mark.parametrize("max", [-1, 0, 0.5, 1, 2])
def test_epss_le(max):
    scores = epss.epss_le(max)
    for s in scores:
        assert s.epss <= max
    for s in list(set(scores) - set(epss.scores())):
        assert s.epss > max


@pytest.mark.parametrize("max", [-1, 0, 0.5, 1, 2])
def test_percentile_le(max):
    scores = epss.percentile_le(max)
    for s in scores:
        assert s.percentile <= max
    for s in list(set(scores) - set(epss.scores())):
        assert s.percentile > max


def test_score():
    score = epss.score(cve_id='CVE-2022-0669')
    assert score.cve.startswith('CVE-')
    assert 0 <= score.epss <= 1
    assert 0 <= score.percentile <= 1
    score = epss.score(cve_id='CVE-1000-123')
    assert score is None


def test_epss():
    score = epss.epss(cve_id='CVE-2022-0669')
    assert 0 <= score <= 1
    score = epss.epss(cve_id='CVE-1000-123')
    assert score is None


def test_percentile():
    score = epss.percentile(cve_id='CVE-2022-0669')
    assert 0 <= score <= 1
    score = epss.percentile(cve_id='CVE-1000-123')
    assert score is None


def test_score_dict():
    score = Score(cve='CVE-2022-39952',
                  epss='0.09029',
                  percentile='0.94031')
    dict_score = score.__dict__
    assert 'cve' in dict_score.keys()
    assert 'epss' in dict_score.keys()
    assert 'percentile' in dict_score.keys()
