import ipaddress
import httpx
import asyncio
import json
from time import time
from typing import List
from . import ioc
from . import secrets


class ipv4ioc(ioc.ioc):
    """ipv4ioc

    Inheriting from the IOC class, we have a specific class for IPv4 indicators.

    The way the class works is that each API endpoint has a function for the specific API endpoint.
    It then passes it onto the querysources function from the IOC superclass which calls all of those
    endpoints.

    You can specify which endpoints are called, and the add more easily by just adding the function
    and the function call.
    """

    def __init__(self, indicator: str):
        try:
            self.api_details = []
            self.api_results = {}
            self.ipv4 = ipaddress.ip_address(indicator)
        except ValueError:
            self.api_results = {
                "indicator": "ipv4",
                "count": 0,
                "time": "00:00",
                "results": "Error - An invalid IPv4 Address Provided",
            }

    def set_url_list(self, url_details: list) -> None:
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
            if self.ipv4.is_global:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
                self._loop.run_until_complete(self.gather_urls())
                super().__init__()
                self.api_results = super().querysources(
                    indicator_type="ipv4", api_endpoint_details=self.api_details
                )
            else:
                self.api_results = {
                    "indicator": "ipv4",
                    "count": 0,
                    "time": 00,
                    "results": "Error - A Local IPv4 Address Provided",
                }
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
            "query_shodan",
            "query_vt",
            "query_greynoise",
            "query_alientvaultotx",
            "query_robtex",
            "query_threatminer_passivedns",
            "query_threatminer_uris",
            "query_threatminer_samples",
        ]
        func_methods = []
        for method in exec_methods:
            func_methods.append(getattr(self, method)())
        res = await asyncio.gather(*func_methods)
        self.set_url_list(res)

    async def query_shodan(self) -> dict:
        """query_shodan
        Returns a dictionary for querying the Shodan API.

        Refer to documentation for details: https://developer.shodan.io/api

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "Shodan"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = None
        source_dict[
            "url"
        ] = f"https://api.shodan.io/shodan/host/{self.ipv4}?key={secrets.SHODAN_API_KEY}"
        return source_dict

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
        source_dict[
            "url"
        ] = f"https://www.virustotal.com/api/v3/ip_addresses/{self.ipv4}"
        return source_dict

    async def query_greynoise(self) -> dict:
        """query_greynoise
        Returns a dictionary for querying the GreyNoise API.

        Refer to documentation for details: https://docs.greynoise.io/docs/using-the-greynoise-community-api

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "GreyNoise"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = {
            "key": f"{secrets.GREYNOISE_API_KEY}",
            "Accept": "application/json",
            "User-Agent": "inspectorgadget/1.0.0",
        }
        source_dict["url"] = f"https://api.greynoise.io/v3/community/{self.ipv4}"
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
        ] = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{self.ipv4}/geo"
        return source_dict

    async def query_robtex(self) -> dict:
        """query_robtex
        Returns a dictionary for querying the Robtex API.

        Refer to documentation for details: https://www.robtex.com/api/

        Parameters
        ----------
        None

        Returns
        -------
        source_dict (dict)
            A dictionary including URL, sourcepoint, HTTP Request type, data (for a POST request), headers and more.
        """
        source_dict = {}
        source_dict["name"] = "Robtex"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = None
        source_dict["url"] = f"https://freeapi.robtex.com/ipquery/{self.ipv4}"
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
                "threatEntries": [
                    {"url": f"http://{self.ipv4}"},
                    {"url": f"https://{self.ipv4}"},
                ],
            },
        }
        source_dict["header"] = {"Content-Type": "application/json"}
        source_dict[
            "url"
        ] = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={secrets.GOOGLESAFEBROWSING_API_KEY}"
        return source_dict

    """
    These functions were a test to gather information about the TOR exit nodes, but unfortunately
    their method doesn't work in this class, so they're currently being ignored.

    async def generate_torexitips(self):
        r = requests.get("https://check.torproject.org/exit-addresses")
        tor_exit_ip_list = []
        for line in r.text.split("\n"):
            values = line.split(" ")
            if values[0] == "ExitAddress":
                tor_exit_ip_list.append(values[1])
        return tor_exit_ip_list

    async def query_torexitips(self):
        source_dict = {}
        source_dict["source"] = "TorExitIPs"
        tor_ip_list = self.generate_torexitips()
        if self.ipv4 in tor_ip_list:
            source_dict["results"] = {"TorExitIP": True}
            return source_dict
        else:
            source_dict["results"] = {"TorExitIP": False}
            return source_dict
    """

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
        ] = f"https://api.threatminer.org/v2/host.php?q={self.ipv4}&rt=2"
        return source_dict

    async def query_threatminer_uris(self) -> dict:
        """query_threatminer_uris
        Returns a dictionary for querying the Threat Miner (URIs) API.

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
        source_dict["name"] = "ThreatMiner_URIs"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = {"Content-Type": "application/json"}
        source_dict[
            "url"
        ] = f"https://api.threatminer.org/v2/host.php?q={self.ipv4}&rt=3"
        return source_dict

    async def query_threatminer_samples(self) -> dict:
        """query_threatminer_samples
        Returns a dictionary for querying the Threat Miner (Samples) API.

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
        source_dict["name"] = "ThreatMiner_Samples"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = {"Content-Type": "application/json"}
        source_dict[
            "url"
        ] = f"https://api.threatminer.org/v2/host.php?q={self.ipv4}&rt=4"
        return source_dict

    async def query_threatminer_sslcerthash(self) -> dict:
        """query_threatminer_sslcerthash
        Returns a dictionary for querying the Threat Miner (SSL Cert hash) API.

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
        source_dict["name"] = "ThreatMiner_SSLCertHash"
        source_dict["type"] = "GET"
        source_dict["data"] = None
        source_dict["header"] = {"Content-Type": "application/json"}
        source_dict[
            "url"
        ] = f"https://api.threatminer.org/v2/host.php?q={self.ipv4}&rt=5"
        return source_dict