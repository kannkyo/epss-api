from __future__ import annotations

import csv
from functools import cached_property
from gzip import GzipFile
from urllib.request import urlopen


class Score(object):
    """ EPSS Score Object"""

    def __init__(self, cve: str, epss: str, percentile: str):
        self.cve = cve
        self.epss = float(epss)
        self.percentile = float(percentile)


class EPSS(object):
    def __init__(self) -> None:
        pass

    def scores(self) -> list[Score]:
        """Get all CVE's EPSS scores (downloaded data is cached in memory)

        Example

        [
        {'cve': 'CVE-2022-39952', 'epss': '0.09029', 'percentile': '0.94031'},
        {'cve': 'CVE-2023-0669', 'epss': '0.78437', 'percentile': '0.99452'},
        ...
        ]

        Returns:
            list[Score]: EPSS score's csv list
        """
        scores = [row for row in csv.DictReader(self._download[1:])]
        return [Score(row['cve'], row['epss'], row['percentile'])
                for row in scores]

    def score(self, cve_id: str) -> Score:
        """Get EPSS score and percentile

        Example
            {'cve': 'CVE-2022-39952', 'epss': 0.0095, 'percentile': 0.32069}

        Args:
            cve_id (str): CVE ID (CVE-nnnn)

        Returns:
            Score | None: EPSS score percentile
        """
        rows = self._filter_by_cve_id(cve_id)
        if len(rows) == 1:
            return rows[0]
        else:
            return None

    def epss(self, cve_id: str) -> float:
        """Get EPSS score

        Args:
            cve_id (str): CVE ID (CVE-nnnn)

        Returns:
            float | None: EPSS score (0.0-1.0)
        """
        rows = self._filter_by_cve_id(cve_id)
        if len(rows) == 1:
            return rows[0].epss
        else:
            return None

    def percentile(self, cve_id: str) -> float:
        """Get EPSS percentile

        Args:
            cve_id (str): CVE ID (CVE-nnnn)

        Returns:
            float | None: EPSS percentile (0.0-1.0)
        """
        rows = self._filter_by_cve_id(cve_id)
        if len(rows) == 1:
            return rows[0].percentile
        else:
            return None

    def epss_gt(self, max: float) -> list[Score]:
        """Get CVEs with EPSS score greater or equal than the parameter

        Args:
            max (float): limit of EPSS score

        Returns:
            list[Score] | None: EPSS score object list
        """
        rows = [r for r in filter(lambda x: x.epss >= max, self.scores())]
        return rows

    def percentile_gt(self, max: float) -> list[Score]:
        """Get CVEs with percentile greater or equal than the parameter

        Args:
            max (float): limit of EPSS score

        Returns:
            list[Score] | None: EPSS score object list
        """
        rows = [r for r in
                filter(lambda x: x.percentile >= max, self.scores())]
        return rows

    def epss_lt(self, min: float) -> list[Score]:
        """Get CVEs with EPSS score lower or equal than the parameter

        Args:
            min (float): limit of EPSS score

        Returns:
            list[Score] | None: EPSS score object list
        """
        rows = [r for r in filter(lambda x: x.epss <= min, self.scores())]
        return rows

    def percentile_lt(self, min: float) -> list[Score]:
        """Get CVEs with percentile lower or equal than the parameter

        Args:
            min (float): limit of EPSS score

        Returns:
            list[Score] | None: EPSS score object list
        """
        rows = [r for r in
                filter(lambda x: x.percentile <= min, self.scores())]
        return rows

    def csv(self) -> list[str]:
        """Get csv data containing all epss scores.

        Example
            #model_version:v2022.01.01,score_date:2023-03-03T00:00:00+0000
            cve,epss,percentile
            CVE-2014-6271,0.96235,0.99992
            CVE-2014-7169,0.83508,0.99607
            ...

        Returns:
            list[str]: csv data
        """
        return self._download

    def _filter_by_cve_id(self, cve_id: str):
        cve_filter = filter(lambda x: x.cve == cve_id, self.scores())
        rows = [row for row in cve_filter]
        return rows

    @cached_property
    def _download(self):
        url = 'https://epss.cyentia.com/epss_scores-current.csv.gz'

        with urlopen(url) as res:
            dec = GzipFile(fileobj=res)
            epss_scores_str: str = dec.read().decode("utf-8")
            epss_scores_list = epss_scores_str.split('\n')

        return epss_scores_list
