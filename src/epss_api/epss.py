from __future__ import annotations

import csv
from functools import cached_property
from gzip import GzipFile
from urllib.request import urlopen
from bisect import bisect_left


class Score(object):
    """ EPSS Score Object"""

    def __init__(self, cve: str, epss: str, percentile: str):
        self.cve = cve
        self.epss = float(epss)
        self.percentile = float(percentile)


class EPSS(object):
    def __init__(self) -> None:

        url = 'https://epss.cyentia.com/epss_scores-current.csv.gz'

        with urlopen(url) as res:
            dec = GzipFile(fileobj=res)
            epss_scores_str: str = dec.read().decode("utf-8")
            epss_scores_list = epss_scores_str.split('\n')

        self._download = epss_scores_list

        scores = [row for row in csv.DictReader(self._download[1:])]

        self._byCVE = {row['cve'] : Score(row['cve'], row['epss'], row['percentile']) for row in scores}

        self._sortedScores = sorted(self._byCVE.values(),key=lambda x:x.percentile) 

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
        return list(self._sortedScores)

    def score(self, cve_id: str) -> Score:
        """Get EPSS score and percentile

        Example
            {'cve': 'CVE-2022-39952', 'epss': 0.0095, 'percentile': 0.32069}

        Args:
            cve_id (str): CVE ID (CVE-nnnn)

        Returns:
            Score | None: EPSS score percentile
        """

        return self._byCVE.get(cve_id,None)

    def epss(self, cve_id: str) -> float:
        """Get EPSS score

        Args:
            cve_id (str): CVE ID (CVE-nnnn)

        Returns:
            float | None: EPSS score (0.0-1.0)
        """
        
        score = self._byCVE.get(cve_id,None)
        if score is None:
            return None
        else:
            return score.epss

    def percentile(self, cve_id: str) -> float:
        """Get EPSS percentile

        Args:
            cve_id (str): CVE ID (CVE-nnnn)

        Returns:
            float | None: EPSS percentile (0.0-1.0)
        """
        score = self._byCVE.get(cve_id,None)
        if score is None:
            return None
        else:
            return score.percentile

    def epss_gt(self, max: float) -> list[Score]:
        """Get CVEs with EPSS score greater or equal than the parameter

        Args:
            max (float): limit of EPSS score

        Returns:
            list[Score] | None: EPSS score object list
        """
        i = bisect_left(self._sortedScores,min,key=lambda x:x.epss)
        
        return list(self._sortedScores[i:])

    def percentile_gt(self, max: float) -> list[Score]:
        """Get CVEs with percentile greater or equal than the parameter

        Args:
            max (float): limit of EPSS score

        Returns:
            list[Score] | None: EPSS score object list
        """
        i = bisect_left(self._sortedScores,min,key=lambda x:x.percentile)
        
        return list(self._sortedScores[i:])

    def epss_lt(self, min: float) -> list[Score]:
        """Get CVEs with EPSS score lower or equal than the parameter

        Args:
            min (float): limit of EPSS score

        Returns:
            list[Score] | None: EPSS score object list
        """
        i = bisect_left(self._sortedScores[::-1],min,key=lambda x:1-x.epss)
        
        return list(self._sortedScores[:len(self.sortedScores)-i])

    def percentile_lt(self, min: float) -> list[Score]:
        """Get CVEs with percentile lower or equal than the parameter

        Args:
            min (float): limit of EPSS score

        Returns:
            list[Score] | None: EPSS score object list
        """
        i = bisect_left(self._sortedScores[::-1],min,key=lambda x:1-x.percentile)
        
        return list(self._sortedScores[:len(self.sortedScores)-i])

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

