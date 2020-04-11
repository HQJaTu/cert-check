# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

# SPDX-License-Identifier: GPL-2.0
# Code in CTLog-class is heavily inspired by https://github.com/theno/ctutlz written by Theodor Nolte.
# This is an object-oriented adaptation of ctutlz.

from enum import Enum
import base64
import hashlib
from datetime import datetime
from .exceptions import CTLogException


class CTLog:
    # https://groups.google.com/forum/#!topic/certificate-transparency/zZwGExvQeiE
    # PENDING:
    #       The Log has requested inclusion in the Log list distributor’s trusted Log list,
    #       but has not yet been accepted.
    #       A PENDING Log does not count as ‘currently qualified’, and does not count as ‘once qualified’.
    # QUALIFIED:
    #       The Log has been accepted by the Log list distributor, and added to the CT checking code
    #       used by the Log list distributor.
    #       A QUALIFIED Log counts as ‘currently qualified’.
    # USABLE:
    #       SCTs from the Log can be relied upon from the perspective of the Log list distributor.
    #       A USABLE Log counts as ‘currently qualified’.
    # FROZEN (READONLY in JSON-schema):
    #       The Log is trusted by the Log list distributor, but is read-only, i.e. has stopped accepting
    #       certificate submissions.
    #       A FROZEN Log counts as ‘currently qualified’.
    # RETIRED:
    #       The Log was trusted by the Log list distributor up until a specific retirement timestamp.
    #       A RETIRED Log counts as ‘once qualified’ if the SCT in question was issued before the retirement timestamp.
    #       A RETIRED Log does not count as ‘currently qualified’.
    # REJECTED:
    #       The Log is not and will never be trusted by the Log list distributor.
    #       A REJECTED Log does not count as ‘currently qualified’, and does not count as ‘once qualified’.
    class KnownCTStates(Enum):
        PENDING = 'pending'
        QUALIFIED = 'qualified'
        USABLE = 'usable'
        READONLY = 'readonly'  # frozen
        RETIRED = 'retired'
        REJECTED = 'rejected'

    key = None  # base-64 encoded, type: str
    log_id = None
    mmd = None  # v1: maximum_merge_delay
    url = None

    # optional ones:
    description = None
    dns = None
    temporal_interval_begin = None
    temporal_interval_end = None
    log_type = None
    state = None  # JSON-schema has: pending, qualified, usable, readonly, retired, rejected
    state_timestamp = None

    # Custom
    operated_by_name = None
    operated_by_emails = None

    def __init__(self, data):
        self.key = data['key']
        self.log_id = data['log_id']
        self.mmd = data['mmd']
        self.url = data['url']
        self.operated_by_name = data['operated_by']['name']
        self.operated_by_emails = data['operated_by']['email']

        # optional ones:
        self.description = data['description'] if 'description' in data else None
        self.dns = data['dns'] if 'dns' in data else None
        if 'temporal_interval' in data:
            self.temporal_interval = datetime.strptime(data['temporal_interval']['start_inclusive'],
                                                       "%Y-%m-%dT%H:%M:%SZ")
            self.temporal_interval_end = datetime.strptime(data['temporal_interval']['end_exclusive'],
                                                           "%Y-%m-%dT%H:%M:%SZ")
        else:
            self.temporal_interval_begin = None
            self.temporal_interval_end = None

        self.log_type = data['log_type'] if 'log_type' in data else None

        if 'state' in data:
            state_str = next(iter(data['state']))
            if state_str in [state.value for state in CTLog.KnownCTStates]:
                state_timestamp_str = data['state'][state_str]['timestamp']
                self.state = next(iter([state for state in CTLog.KnownCTStates if state.value == state_str]))
                self.state_timestamp = datetime.strptime(state_timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
            else:
                self.state = None
                self.state_timestamp = None
        else:
            self.state = None
            self.state_timestamp = None

    def key_der(self):
        key = base64.b64decode(self.key)

        return key

    def log_id_der(self):
        log_id = base64.b64decode(self.log_id)
        digest = hashlib.sha256(log_id).digest()

        return digest

    def pubkey(self):
        key = '\n'.join(['-----BEGIN PUBLIC KEY-----',
                         text_with_newlines(text=self.key, line_length=64),
                         '-----END PUBLIC KEY-----'])

        return key

    def scts_accepted_by_chrome(self):
        if self.state is None:
            return None

        if next(iter(self.state)) in [CTLog.KnownCTStates.USABLE,
                                      CTLog.KnownCTStates.QUALIFIED,
                                      CTLog.KnownCTStates.READONLY]:
            return True

        return False
