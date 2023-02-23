# %%
import csv
from functools import cached_property
from gzip import GzipFile
from urllib.request import urlopen


class EPSS(object):
    def __init__(self) -> None:
        pass

    def _filter_by_cve_id(self, cve_id: str):
        cve_filter = filter(lambda x: x['cve'] == cve_id, self.scores)
        rows = [row for row in cve_filter]
        return rows

    def epss(self, cve_id: str):
        """Get EPSS score

        Args:
            cve_id (str): CVE ID (CVE-nnnn)

        Returns:
            float | None: EPSS score (0.0-1.0)
        """
        rows = self._filter_by_cve_id(cve_id)
        if len(rows) == 1:
            return float(rows[0]['epss'])
        else:
            return None

    def percentile(self, cve_id: str):
        """Get EPSS percentile

        Args:
            cve_id (str): CVE ID (CVE-nnnn)

        Returns:
            float | None: EPSS percentile (0.0-1.0)
        """
        rows = self._filter_by_cve_id(cve_id)
        if len(rows) == 1:
            return float(rows[0]['percentile'])
        else:
            return None

    def score(self, cve_id: str):
        """Get EPSS score and percentile

        Example
            {'epss': 0.0095, 'percentile': 0.32069}

        Args:
            cve_id (str): CVE ID (CVE-nnnn)

        Returns:
            list | None: EPSS score percentile
        """
        rows = self._filter_by_cve_id(cve_id)
        if len(rows) == 1:
            return {'epss': float(rows[0]['epss']),
                    'percentile': float(rows[0]['percentile'])}
        else:
            return None

    @cached_property
    def scores(self):
        """Download EPSS scores (downloaded data is cached in memory)

        Example

            [
                {'cve': 'CVE-2022-39952', 'epss': '0.09029', 'percentile': '0.94031'},
                {'cve': 'CVE-2023-0669', 'epss': '0.78437', 'percentile': '0.99452'},
                ...
            ]

        Returns:
            list: EPSS score's csv list
        """
        url = 'https://epss.cyentia.com/epss_scores-current.csv.gz'
        with urlopen(url) as res:
            dec = GzipFile(fileobj=res)
            epss_scores_str: str = dec.read().decode("utf-8")
            epss_scores_list = epss_scores_str.split('\n')
            scores = [row for row in csv.DictReader(epss_scores_list[1:])]
        return scores

# %%
