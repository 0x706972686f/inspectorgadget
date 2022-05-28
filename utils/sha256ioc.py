import httpx
import asyncio
import json
from time import time
from typing import List
from . import ioc
from . import secrets


class sha256ioc(ioc.ioc):
    """sha256ioc

    Inheriting from the IOC class, we have a specific class for SHA256 hash indicators.

    The way the class works is that each API endpoint has a function for the specific API endpoint.
    It then passes it onto the querysources function from the IOC superclass which calls all of those
    endpoints.

    You can specify which endpoints are called, and the add more easily by just adding the function
    and the function call.
    """

    def __init__(self, indicator: str):
        self.api_details = []
        self.api_results = {}
        if len(indicator) == 64:
            self.sha256 = indicator
        else:
            self.api_results = {
                "indicator": "sha256",
                "count": 0,
                "time": "00:00",
                "results": "Error - An invalid SHA256 Hash Provided",
            }

    def set_url_list(self, url_details) -> None:
        """set_url_list
        Updates the list of endpoints to query.

        Parameters
        ----------
        url_details (list)
            A list of dictionary items for each API endpoint.

        Returns
        -------
        None
        """
        self.api_details = url_details

    def get_result(self) -> dict:
        """get_results
        Retrieves all of the information needed for each API endpoint by simultaneously calling the functions.
        Then passes that to the IOC superclass querysources function to retrieve the data from them.

        Parameters
        ----------
        url_details (list)
            A list of dictionary items for each API endpoint.

        Returns
        -------
        api_results (dict)
            A dictionary of the details from the API endpoints, or the error.
        """
        if self.api_results:
            return self.api_results
        else:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self.gather_urls())
            super().__init__()
            self.api_results = super().querysources(
                indicator_type="sha256", api_endpoint_details=self.api_details
            )
            return self.api_results

    async def gather_urls(self) -> None:
        """gather_urls
        This function gathers a list of the functions that represent each API endpoint, then
        query them all. Once is has the details it updates set_url_list with the details.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        exec_methods = [
            "query_malwarebazaar",
            "query_vt",
            "query_alientvaultotx",
            "query_threatminer_avdetections",
            "query_threatminer_metadata",
        ]
        func_methods = []
        for method in exec_methods:
            func_methods.append(getattr(self, method)())
        res = await asyncio.gather(*func_methods)
        self.set_url_list(res)

    async def query_vt(self) -> dict:
        """query_vt
        Returns a dictionary for querying the VirusTotal API.

        Refer to documentation for details: https://developers.virustotal.com/reference/ip-info

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "VirusTotal"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = {
            "x-apikey": f"{secrets.VIRUSTOTAL_API_KEY}",
            "Accept": "application/json",
        }
        source_dict["url"] = f"https://www.virustotal.com/api/v3/files/{self.sha256}"
        return source_dict

    async def query_alientvaultotx(self) -> dict:
        """query_alientvaultotx
        Returns a dictionary for querying the OTX AlienVault API.

        Refer to documentation for details: https://otx.alienvault.com/api

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "AlienVaultOTX"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = {"x-otx-api-key": f"{secrets.ALIENVAULTOTX_API_KEY}"}
        source_dict[
            "url"
        ] = f"https://otx.alienvault.com/api/v1/indicators/file/{self.sha256}/general"
        return source_dict

    async def query_threatminer_metadata(self) -> dict:
        """query_threatminer_metadata
        Returns a dictionary for querying the Threat Miner (File Metadata) API.

        Refer to documentation for details: https://www.threatminer.org/api.php

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "ThreatMiner_Metadata"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = {"Content-Type": "application/json"}
        source_dict[
            "url"
        ] = f"https://api.threatminer.org/v2/sample.php?q={self.sha256}&rt=1"
        return source_dict

    async def query_threatminer_avdetections(self) -> dict:
        """query_threatminer_avdetections
        Returns a dictionary for querying the Threat Miner (AV Detections) API.

        Refer to documentation for details: https://www.threatminer.org/api.php

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "ThreatMiner_AVDetections"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = {"Content-Type": "application/json"}
        source_dict[
            "url"
        ] = f"https://api.threatminer.org/v2/sample.php?q={self.sha256}&rt=6"
        return source_dict

    async def query_malwarebazaar(self) -> dict:
        """query_malwarebazaar
        Returns a dictionary for querying Malware Bazaar API.

        Refer to documentation for details: https://bazaar.abuse.ch/api/#query_hash

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "MalwareBazaar"
        source_dict["type"] = "POST"
        source_dict["data"] = {"query": "get_info", "hash": f"{self.sha256}"}
        source_dict["header"] = {"API-KEY": f"{secrets.MALWAREBAZAAR_API_KEY}"}
        source_dict["url"] = "https://mb-api.abuse.ch/api/v1/"
        return source_dict

    async def query_triage(self) -> dict:
        """query_triage
        Returns a dictionary for querying Tria.ge API.

        Refer to documentation for details: https://tria.ge/docs/cloud-api/samples/#get-samplessampleid

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "Tria.ge"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = {"Authorization": f"Bearer {secrets.TRIAGE_API_KEY}"}
        source_dict["url"] = f"https://api.tria.ge/v0/search?query=sha256:{self.sha256}"
        return source_dict