# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

# SPDX-License-Identifier: GPL-2.0
# Code in CTLog-class is heavily inspired by https://github.com/theno/ctutlz written by Theodor Nolte.
# This is an object-oriented adaptation of ctutlz.

import aiohttp
import asyncio
import socket
import os.path
import pickle
from datetime import datetime, timezone
import json
import base64
from .ct_log import CTLog
from .exceptions import CTLogException


class CTLogList:
    # For list of logs, see: https://www.certificate-transparency.org/known-logs
    all_logs_list_url = 'https://www.gstatic.com/ct/log_list/v2/all_logs_list.json'
    cache_file = None
    logs = None

    def __init__(self, cache_file='/tmp/.cert_check_ct_log.dat'):
        self.cache_file = cache_file

    def has_logs(self):
        if self.logs:
            return True
        return False

    def find_log(self, id):
        if not self.logs:
            raise CTLogException("Uninitialized. No logs to search from!")

        id_base64 = base64.b64encode(id).decode('ascii')
        if self.logs and id_base64 in self.logs['logs']:
            return self.logs['logs'][id_base64]

        return None

    async def get_logs_async(self, loop, allow_cache=True):
        if allow_cache and os.path.exists(self.cache_file):
            with open(self.cache_file, "rb") as logs_file:
                self.logs = pickle.load(logs_file)
            return True

        # Go get the data
        response, response_str = await CTLogList.load_ct_v2_json_async(loop)
        if response.status != 200:
            raise CTLogException("Failed to load all logs list from %s" % CTLogList.all_logs_list_url)

        logs_dict = json.loads(response_str)

        # Post-process.
        # Reset internal storage
        self.logs = {
            'updated': datetime.now(timezone.utc),
            'logs': {}
        }

        # Iterate and copy
        for operator in logs_dict['operators']:
            operator_name = operator['name']
            operator_email = operator['email']
            for log in operator['logs']:
                log_id = log['log_id']
                log['operated_by'] = {
                    'name': operator_name,
                    'email': operator_email
                }

                log_obj = CTLog(log)
                self.logs['logs'][log_id] = log_obj

        # Serialize to disc for later use
        with open(self.cache_file, "wb") as logs_file:
            pickle.dump(self.logs, logs_file)

        return True

    @staticmethod
    def load_ct_v2_json(self):
        raise NotImplementedError("Use asyncio load_ct_v2_json_async() !")

    @staticmethod
    async def load_ct_v2_json_async(loop, timeout=30.0):
        aio_timeout = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=aio_timeout, loop=loop, raise_for_status=True) as session:
            try:
                async with session.get(CTLogList.all_logs_list_url) as response:
                    return response, await response.read()
            except (aiohttp.ClientError, aiohttp.ClientConnectorError, socket.gaierror):
                return None, None
            except asyncio.TimeoutError:
                return None, None
