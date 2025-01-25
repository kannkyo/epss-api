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
    >>> from epss_api import EPSS
    >>> 
    >>> client = EPSS()

    >>> print(client.scores()[0])
    {'cve': 'CVE-1999-0013', 'epss': 0.00042, 'percentile': 0.05071}

    >>> print(client.score('CVE-2024-0001'))
    {'cve': 'CVE-2024-0001', 'epss': 0.00091, 'percentile': 0.4063}

    >>> print(client.csv()[1])
    cve,epss,percentile

    >>> print(client.epss('CVE-2024-0001'))
    0.00091

    >>> print(client.epss_ge(0.50003)[0])
    {'cve': 'CVE-2022-0651', 'epss': 0.50003, 'percentile': 0.97652}

    >>> print(client.epss_gt(0.50003)[0])
    {'cve': 'CVE-2018-0851', 'epss': 0.50036, 'percentile': 0.97653}

    >>> print(client.epss_le(0.49982)[-1])
    {'cve': 'CVE-2014-8074', 'epss': 0.49982, 'percentile': 0.97651}

    >>> print(client.epss_lt(0.49982)[-1])
    {'cve': 'CVE-2018-8011', 'epss': 0.49981, 'percentile': 0.97651}

    >>> print(client.percentile('CVE-2024-0001'))
    0.4063

    >>> print(client.percentile_ge(0.5)[0])
    {'cve': 'CVE-2019-5426', 'epss': 0.00137, 'percentile': 0.5}

    >>> print(client.percentile_gt(0.5)[0])
    {'cve': 'CVE-2021-43464', 'epss': 0.00137, 'percentile': 0.50004}

    >>> print(client.percentile_le(0.5)[-1])
    {'cve': 'CVE-2022-27777', 'epss': 0.00137, 'percentile': 0.5}

    >>> print(client.percentile_lt(0.5)[-1])
    {'cve': 'CVE-2021-1625', 'epss': 0.00137, 'percentile': 0.49999}

If you call either one method, EPSS client cache all CVE's score in memory.
After caching, you can get all data very fast.
