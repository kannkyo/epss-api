=================
EPSS API Client
=================

.. image:: https://badge.fury.io/py/epss-api.svg
    :target: https://badge.fury.io/py/epss-api

.. image:: https://img.shields.io/pypi/dw/epss-api?style=flat
    :target: https://pypistats.org/packages/epss-api

.. image:: https://github.com/kannkyo/epss-api/actions/workflows/python-ci.yml/badge.svg
    :target: https://github.com/kannkyo/epss-api/actions/workflows/python-ci.yml

.. image:: https://codecov.io/gh/kannkyo/epss-api/branch/main/graph/badge.svg?token=R40FT0KITO 
    :target: https://codecov.io/gh/kannkyo/epss-api

.. image:: https://github.com/kannkyo/epss-api/actions/workflows/scorecards.yml/badge.svg
    :target: https://github.com/kannkyo/epss-api/actions/workflows/scorecards.yml

EPSS(Exploit Prediction Scoring System) API client.

EPSS is the one of famous vulnerability score developed by FIRST (the Forum of Incident Response and Security Teams).

EPSS's definition:

    The Exploit Prediction Scoring System (EPSS) is an open, 
    data-driven effort for estimating the likelihood (probability) that a software vulnerability will be exploited in the wild. 
    Our goal is to assist network defenders to better prioritize vulnerability remediation efforts. 
    While other industry standards have been useful for capturing innate characteristics of a vulnerability and provide measures of severity, 
    they are limited in their ability to assess threat. 
    EPSS fills that gap because it uses current threat information from CVE and real-world exploit data. 
    The EPSS model produces a probability score between 0 and 1 (0 and 100%). 
    The higher the score, the greater the probability that a vulnerability will be exploited.

    https://www.first.org/epss/

This package is most easiest and efficient EPSS api client.

Usage
=============

EPSS has some methods.

.. code-block:: python

    from epss_api import EPSS

    client = EPSS()

    value = client.scores()
    # value = [
    #   {'cve': 'CVE-2022-39952', 'epss': '0.09029', 'percentile': '0.94031'},
    #   {'cve': 'CVE-2023-0669', 'epss': '0.78437', 'percentile': '0.99452'},
    #  ...
    # ]

    value = client.epss_lt(0.5)
    # value = [
    #   {'cve': 'CVE-2022-39952', 'epss': '0.09029', 'percentile': '0.24031'},
    #   {'cve': 'CVE-2023-0669', 'epss': '0.18437', 'percentile': '0.19452'},
    #  ...
    # ]

    value = client.percentile_lt(0.5)
    # value = [
    #   {'cve': 'CVE-2022-39952', 'epss': '0.09029', 'percentile': '0.24031'},
    #   {'cve': 'CVE-2023-0669', 'epss': '0.78437', 'percentile': '0.19452'},
    #  ...
    # ]

    value = client.epss_gt(0.5)
    # value = [
    #   {'cve': 'CVE-2022-39952', 'epss': '0.59029', 'percentile': '0.94031'},
    #   {'cve': 'CVE-2023-0669', 'epss': '0.78437', 'percentile': '0.99452'},
    #  ...
    # ]

    value = client.percentile_gt(0.5)
    # value = [
    #   {'cve': 'CVE-2022-39952', 'epss': '0.59029', 'percentile': '0.94031'},
    #   {'cve': 'CVE-2023-0669', 'epss': '0.78437', 'percentile': '0.99452'},
    #  ...
    # ]

    value = client.score(cve_id='CVE-2022-0669')
    # value = {'cve': 'CVE-2022-39952', 'epss': 0.0095, 'percentile': 0.32069}

    value = client.epss(cve_id='CVE-2022-0669')
    # value == 0.0095

    value = client.percentile(cve_id='CVE-2022-0669')
    # value == 0.32069

If you call either one method, EPSS client cache all CVE's score in memory.
After caching, you can get all data very fast.
