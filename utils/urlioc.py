import ipaddress
import httpx
import asyncio
import json
import validators
from time import time
from typing import List
from validators import ValidationFailure
from . import ioc
from . import secrets


class urlioc(ioc.ioc):
    """urlioc

    Inheriting from the IOC class, we have a specific class for SHA256 hash indicators.

    The way the class works is that each API endpoint has a function for the specific API endpoint.
    It then passes it onto the querysources function from the IOC superclass which calls all of those
    endpoints.

    You can specify which endpoints are called, and the add more easily by just adding the function
    and the function call.
    """

    def __init__(self, indicator):
        self.api_details = []
        self.api_results = {}
        validate_url = validators.url(indicator.strip())
        if isinstance(validate_url, ValidationFailure):
            self.url = None
            self.api_results = {
                "indicator": "url",
                "count": 0,
                "time": 00,
                "results": "Error - Invalidate URL Provided",
            }
        else:
            self.url = indicator

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
                indicator_type="url", api_endpoint_details=self.api_details
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
            "query_vt",
            "query_alientvaultotx",
            "query_googlesafebrowsing",
            "query_threatminer_passivedns",
            "query_threatminer_whois",
            "query_urlhaus",
            "query_crtsh",
            "query_screenshotapi",
            "query_urlscan",
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
        source_dict["url"] = f"https://www.virustotal.com/api/v3/urls/{self.url}"
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
        ] = f"https://otx.alienvault.com/api/v1/indicators/url/{self.url}/general"
        return source_dict

    async def query_googlesafebrowsing(self) -> dict:
        """query_googlesafebrowsing
        Returns a dictionary for querying the Google Safe Browsing API.

        Refer to documentation for details: https://developers.google.com/safe-browsing/v4/lookup-api

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "GoogleSafeBrowsing"
        source_dict["type"] = "POST"
        source_dict["data"] = {
            "client": {"clientId": "InspectorGadget", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["PLATFORM_TYPE_UNSPECIFIED"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": f"{self.url}"}],
            },
        }
        source_dict["header"] = {"Content-Type": "application/json"}
        source_dict[
            "url"
        ] = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={secrets.GOOGLESAFEBROWSING_API_KEY}"
        return source_dict

    async def query_threatminer_passivedns(self) -> dict:
        """query_threatminer_passivedns
        Returns a dictionary for querying the Threat Miner (Passive DNS) API.

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
        source_dict["name"] = "ThreatMiner_PassiveDNS"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = {"Content-Type": "application/json"}
        source_dict[
            "url"
        ] = f"https://api.threatminer.org/v2/domain.php?q={self.url}&rt=2"
        return source_dict

    async def query_threatminer_whois(self) -> dict:
        """query_threatminer_whois
        Returns a dictionary for querying the Threat Miner (Whois) API.

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
        source_dict["name"] = "ThreatMiner_WHOIS"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = {"Content-Type": "application/json"}
        source_dict[
            "url"
        ] = f"https://api.threatminer.org/v2/domain.php?q={self.url}&rt=2"
        return source_dict

    async def query_urlhaus(self) -> dict:
        """query_urlhaus
        Returns a dictionary for querying the URLHaus API.

        Refer to documentation for details: https://urlhaus-api.abuse.ch/

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "URLHaus"
        source_dict["type"] = "POST"
        source_dict["data"] = {"url": f"{self.url}"}
        source_dict["header"] = None
        source_dict["url"] = "https://urlhaus-api.abuse.ch/v1/url/"
        return source_dict

    async def query_crtsh(self) -> dict:
        """query_crtsh
        Returns a dictionary for querying the crt.sh API.

        Refer to documentation for details: https://github.com/PaulSec/crt.sh/blob/master/crtsh.py

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "crt.sh"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = None
        source_dict["url"] = f"https://crt.sh/?q={self.url}&output=json"
        return source_dict

    async def query_screenshotapi(self) -> dict:
        """query_screenshotapi
        Returns a dictionary for querying the ScreenShot API API.

        Refer to documentation for details: https://docs.screenshotapi.net/

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "ScreenShotAPI"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = None
        source_dict[
            "url"
        ] = f"https://shot.screenshotapi.net/screenshot?token={secrets.SCREENSHOTAPI_API_KEY}&url={self.url}&extract_text=true&full_page=true&fresh=true&output=json&file_type=png&wait_for_event=load"
        return source_dict

    async def query_urlscan(self) -> dict:
        """query_screenshotapi
        Returns a dictionary for querying the URLScan API.

        Refer to documentation for details: https://urlscan.io/docs/api/

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "URLScan"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = {
            "Content-Type": "application/json",
            "API-Key": f"{secrets.URLSCANIO_API_KEY}",
        }
        source_dict["url"] = f"https://urlscan.io/api/v1/search/?q=page.url:{self.url}"
        return source_dict