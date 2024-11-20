# pylint: disable=R0913
"""
    Implement caching for IP lookup
"""

import json.decoder
import os
import ipaddress
import logging
from datetime import datetime
from dateutil.relativedelta import relativedelta

DEFAULT_CACHE_FILE = "ip_networks_cache.json"
NOT_FOUND_FILE = "not_found_list.txt"
CACHE_TIMEOUT_DAYS = 14


class JsonFields:
    """
        Class, describing cache JSON fields
    """
    ADDRESS = "address"
    CIDR = "cidr"
    DESCRIPTION = "description"
    NAME = "name"
    COUNTRY = "country"
    REGISTRY = "registry"
    FQDN = "fqdn"
    CREATED = "created"


class ResolvedNetwork:
    """
        Class-container for the information about network, received from RIR
    """
    address: str = ""
    description: str = ""
    name: str = ""
    cidr: str = ""
    country: str = ""
    registry: str = ""
    fqdn: str = ""
    created: str = ""

    def __init__(self, address: str = "", cidr: str = "", description: str = "", name: str = "",
                 country: str = "", registry: str = "", fqdn: str = "", **kwargs):
        """
            The constructor accepts either a set of parameters or a JSON could passed to it.

            :param str address: IPv4 address or network as string
            :param str cidr: the subnet that includes address
            :param str description: subnet description from RIR
            :param str name: subnet name from RIR
            :param str country: country, where subnet is registered
            :param str registry: name of the RIR, responsible for the subnet
            :param str fqdn: FQDN that IP address resolved to

            Kwargs:
            :key json: dictionary, representing a JSON

        """
        js = kwargs.get("json")

        if js is None:
            self.address = address
            self.description = description
            self.name = name
            self.cidr = cidr
            self.country = country
            self.registry = registry
            self.fqdn = fqdn

        if js is not None:
            self.address = js[JsonFields.ADDRESS]
            self.cidr = js[JsonFields.CIDR]
            self.description = js[JsonFields.DESCRIPTION]
            self.name = js[JsonFields.NAME]
            self.country = js[JsonFields.COUNTRY]
            self.registry = js[JsonFields.REGISTRY]
            self.fqdn = js[JsonFields.FQDN]

    def to_dict(self) -> dict:
        """
            Convert object to dict/JSON
        """
        return self.__dict__.copy()

    def __str__(self) -> str:
        """
            Convert object to multiline string
        """
        return (f"{self.address}:\n"
                f"{'-':>7} Name: {self.name}\n"
                f"{'-':>7} Description: {self.description}\n"
                f"{'-':>7} CIDR: {self.cidr}\n"
                f"{'-':>7} Country: {self.country}\n"
                f"{'-':>7} Registry: {self.registry}\n"
                f"{'-':>7} FQDN: {self.fqdn}\n")


class NetworkCache():
    """
        Implements file-based caching to avoid redundant lookups by RIRs
        and thus rate-limiting on their end
    """
    # List of CIDR that were not resolved
    not_found: list = []
    # { CIDR : { attr: value } }
    cache: dict[str, dict[str,str]] = {}
    # map IPv4Network object to CIDR as string for cache lookup
    net_to_cidr: dict[ipaddress.IPv4Network, str] = {}

    def __init__(self, cache_file: str):
        """
            Load existing cache file, if present
        """
        if os.path.isfile(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as cachedata:
                    self.cache = json.load(cachedata)

            except json.decoder.JSONDecodeError as e:
                logging.error("Error with loading %s - Ensure this file is not corrupted\n%s",
                              cache_file,
                              str(e))
                return

            stale_keys = []
            now = datetime.now()
            time_window = relativedelta(days=+CACHE_TIMEOUT_DAYS)
            for entry in self.cache:
                str_date = self.cache[entry].get(JsonFields.CREATED)
                if str_date is None:
                    stale_keys.append(entry)
                    continue

                expiry_date = datetime.fromisoformat(str_date) + time_window
                if expiry_date <= now:
                    stale_keys.append(entry)

            for key in stale_keys:
                del self.cache[key]

            self.net_to_cidr = {ipaddress.ip_network(CIDR): CIDR for CIDR in self.cache.keys()}

    def save_cache(self, cache_file: str = DEFAULT_CACHE_FILE) -> None:
        """
            Persist cache to disk

            :param str cache_file: path to cache file; optional
        """
        with open(cache_file, "w", encoding="utf-8") as file_obj:
            json.dump(self.cache, file_obj, indent=4)

    def save_not_found(self) -> None:
        """
            Dump entries, that were not found, to disk, and reset the list
        """
        if len(self.not_found) == 0:
            return

        with open(NOT_FOUND_FILE, "a", encoding="utf-8") as file_obj:
            file_obj.write('\n'.join(self.not_found))

        self.not_found = []

    def set(self, network: str, name: str, description: str,
            country: str, registry: str, fqdn: str) -> None:
        """
            Add an entry to the cache in-memory

            :param str network: CIDR as stored in RIR database
            :param str name: name of the network, received from RIR
            :param str description: description of the network, received from RIR
            :param str country: country, where CIDR is registered
            :param str registry: RIR, responsible for the CIDR
            :param str fqdn: FQDN that the hostname resolves to (/32 or hosts only)
        """
        self.cache[network] = {
            JsonFields.NAME: name,
            JsonFields.DESCRIPTION: description,
            JsonFields.COUNTRY: country,
            JsonFields.REGISTRY: registry,
            JsonFields.FQDN: fqdn,
            JsonFields.CREATED: datetime.now().isoformat()
        }

        # add to networks hash
        try:
            self.net_to_cidr[ipaddress.ip_network(network)] = network
        except ValueError:
            logging.error("Value error adding network to cache. network=%s _ name=%s",
                          network, name)

    def _get(self, address: str, network: str) -> dict[str,str]:
        """
            Get network data from cache by CIDR as JSON

            :param str address: value to be translated by RIR
            :param str network: CIDR that matches address

            :return dict[str,str]: dict, corresponding to JSON entry in cache
        """
        net_name: str = self.cache[network][JsonFields.NAME]
        net_country: str = self.cache[network][JsonFields.COUNTRY]
        net_description: str = self.cache[network][JsonFields.DESCRIPTION]
        net_registry: str = self.cache[network][JsonFields.REGISTRY]
        net_rdns_fqdn: str = self.cache[network][JsonFields.FQDN]

        return {JsonFields.ADDRESS: address, JsonFields.CIDR: network, JsonFields.NAME: net_name,
                JsonFields.COUNTRY: net_country, JsonFields.REGISTRY: net_registry,
                JsonFields.DESCRIPTION: net_description, JsonFields.FQDN: net_rdns_fqdn }

    def get_network(self, address: str, network: str) -> ResolvedNetwork:
        """
            Get network data from cache by CIDR as ResolvedNetwork

            :param str address: value to be translated by RIR
            :param str network: CIDR that matches address

            :return ResolvedNetwork: object, corresponding to JSON entry in cache
        """
        return ResolvedNetwork(json=self._get(address, network))

    def in_cache(self, address: ipaddress.IPv4Address) -> str | None:
        """
            Check, whether IP address is included in any cache entries, by searching
            the CIRR-to-IPv4Network map for a match
        """
        for net in self.net_to_cidr.keys():
            if address in net:
                return self.net_to_cidr[net]

        return None
