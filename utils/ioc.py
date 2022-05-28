import ipaddress
import httpx
import asyncio
import json
from time import time
from typing import List


class ioc(object):
    """IOC

    This library is for querying API endpoints to gather information about an IOC.

    This class is the superclass that is the basis for other IOC types (SHA256 hashes, IPv4 addresses, URLs, etc).

    By having a base IOC class, the heavy lifting for the simultaneous HTTP connections can be done here.

    It works by gathering a dictionary of parameters for an API request, such as URL, headers, useragent, etc,
    calling a function that builds out each request, them simultaneously running each function. In doing so
    it's like a shotgun blast to API endpoints for indicator information and reducing the wait time for
    information due to the parallalism.
    """

    def __init__(self):
        self.q = asyncio.Queue(maxsize=100)
        self.response = []
        self.consumers = []
        self.producers = []
        self.source_url_count = 0
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

    async def client(self, api_url_details: dict, val: int) -> str:
        """client
        Client function makes the HTTP client request to the API endpoint.

        Parameters
        ----------
        api_url_details (dict)
            A dictionary of parameters used for the HTTP request.
        val (int)
            A count of the amount of API endpoints to reach.

        Returns
        -------
        r.text (str)
            The response text from the HTTP request.
        """
        async with httpx.AsyncClient() as client:
            url = api_url_details["url"]
            if api_url_details["header"]:
                headers = api_url_details["header"]
            else:
                headers = {"User-Agent": "myapp/0.0.1"}

            if api_url_details["data"]:
                data = api_url_details["data"]
            else:
                data = None
            req = httpx.Request(
                api_url_details["type"], url, headers=headers, json=data
            )
            r = await client.send(req)
            return r.text

    async def producer(
        self, queue: asyncio.Queue, api_url_details: dict, val: int
    ) -> None:
        """producer
        Adds each client function call to a queue.

        Parameters
        ----------
        api_url_details (dict)
            A dictionary of parameters used for the HTTP request.
        val (int)
            A count of the amount of API endpoints to reach.

        Returns
        -------
        None
        """
        await queue.put(lambda: self.client(api_url_details, val))

    async def consumer(self, queue: asyncio.Queue, resp: list, name: str) -> None:
        """consumer
        Runs the function in the queue, adding the results to a dictionary.

        Parameters
        ----------
        queue (asyncio.Queue)
            The asyncio.Queue with all of the functions stored inside.
        resp (list)
            An array of the results, which get appended to it.
        name (str)
            The name of the source.

        Returns
        -------
        None
        """
        placeholder = {}
        placeholder["source"] = name
        try:
            placeholder["results"] = json.loads(await (await queue.get())())
        except Exception as err:
            placeholder["results"] = "Error retrieving information."
        resp.append(placeholder)

    async def task(self, URL: list) -> tuple(str, int):
        """task
        This function creates the queues, and builds up the functions before running them all at the same time.
        It gathers the results together into one place.

        Parameters
        ----------
        URL (list)
            A list of dictionaries making up the API endpoint request information.

        Returns
        -------
        response (list)
            The combined list of dictionaries for each response
        len(response) (int)
            The count of responses received.
        """
        for u in URL:
            self.consumers.append(self.consumer(self.q, self.response, u["name"]))
            self.producers.append(self.producer(self.q, u, self.source_url_count))
            self.source_url_count += 1

        await asyncio.gather(*self.producers)
        await asyncio.gather(*self.consumers)
        return self.response, len(self.response)

    def querysources(self, indicator_type: str, api_endpoint_details: list) -> dict:
        """querysources
        This function kicks off the asyncio loop that is the 'shotgun blast' of requests.
        It also wraps the results in a dictionary for easy access.

        Parameters
        ----------
        indicator_type (str)
            The type of indicator it is (SHA256, URL, IPv4)
        api_endpoint_details (list)
            A list of dictionaries with all the information needed to make an API request to that endpoint

        Returns
        -------
        response_json (dict)
            A dictionary comprised of all the data from the API endpoints.
        """
        start = time()
        res, val = self._loop.run_until_complete(self.task(api_endpoint_details))
        end = time()
        response_json = {}
        response_json["indicator"] = indicator_type
        response_json["count"] = val
        response_json["time"] = f"{end - start:.2f}"
        response_json["results"] = res
        return response_json
