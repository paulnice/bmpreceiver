#!/usr/bin/python2.5
#
# Copyright 2009 Google Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Border Gateway Protocol - various constants and functions."""

__author__ = 'sstuart@google.com (Stephen Stuart)'
__version__ = '4.0'

import math

# In general, see RFC4271 for details.
#
# The length of the fixed header part of a BGP message.
#
HEADER_LEN = 19

# Message types.
#
OPEN = 1
UPDATE = 2
NOTIFICATION = 3
KEEPALIVE = 4
MSG_TYPE_STR = {OPEN: 'OPEN',
                UPDATE: 'UPDATE',
                NOTIFICATION: 'NOTIFICATION',
                KEEPALIVE: 'KEEPALIVE'}

# Attribute types.
#
ATTR_TYPE_ORIGIN = 1
ATTR_TYPE_AS_PATH = 2
ATTR_TYPE_NEXT_HOP = 3
ATTR_TYPE_MULTI_EXIT_DISC = 4
ATTR_TYPE_LOCAL_PREF = 5
ATTR_TYPE_ATOMIC_AGGREGATE = 6
ATTR_TYPE_AGGEGATOR = 7
ATTR_TYPE_COMMUNITIES = 8
ATTR_TYPE_ORIGINATOR_ID = 9
ATTR_TYPE_CLUSTER_LIST = 10
ATTR_TYPE_DPA = 11
ATTR_TYPE_ADVERTISER = 12
ATTR_TYPE_RCID_PATH = 13
ATTR_TYPE_MP_REACH_NLRI = 14
ATTR_TYPE_MP_UNREACH_NLRI = 15
ATTR_TYPE_AS4_PATH = 17
ATTR_TYPE_AS4_AGGREGATOR = 18

ATTR_TYPE_STR = {ATTR_TYPE_ORIGIN: 'ORIGIN',
                 ATTR_TYPE_AS_PATH: 'AS_PATH',
                 ATTR_TYPE_NEXT_HOP: 'NEXT_HOP',
                 ATTR_TYPE_MULTI_EXIT_DISC: 'MULTI_EXIT_DISC',
                 ATTR_TYPE_LOCAL_PREF: 'LOCAL_PREF',
                 ATTR_TYPE_ATOMIC_AGGREGATE: 'ATOMIC_AGGREGATE',
                 ATTR_TYPE_AGGEGATOR: 'AGGREGATOR',
                 ATTR_TYPE_COMMUNITIES: 'COMMUNITIES',
                 ATTR_TYPE_ORIGINATOR_ID: 'ORIGINATOR_ID',
                 ATTR_TYPE_CLUSTER_LIST: 'CLUSTER_LIST',
                 ATTR_TYPE_DPA: 'DPA',
                 ATTR_TYPE_ADVERTISER: 'ADVERTISER',
                 ATTR_TYPE_RCID_PATH: 'RCID_PATH',
                 ATTR_TYPE_MP_REACH_NLRI: 'MP_REACH_NLRI',
                 ATTR_TYPE_MP_UNREACH_NLRI: 'MP_UNREACH_NLRI',
                 ATTR_TYPE_AS4_PATH: 'AS4_PATH',
                 ATTR_TYPE_AS4_AGGREGATOR: 'AS4_AGGREGATOR'}

# Attribute flag values.
#
ATTR_FLAG_OPTIONAL = 128
ATTR_FLAG_TRANSITIVE = 64
ATTR_FLAG_PARTIAL = 32
ATTR_FLAG_EXT_LEN = 16

# Values for the ORIGIN attribute.
#
ORIGIN_IGP = 0
ORIGIN_EGP = 1
ORIGIN_INCOMPLETE = 2
ORIGIN_STR = {ORIGIN_IGP: 'IGP',
              ORIGIN_EGP: 'EGP',
              ORIGIN_INCOMPLETE: 'incomplete'}

# AS_PATH attribute path segment type codes.
#
AS_SET = 1
AS_SEQUENCE = 2
AS_CONFED_SET = 3
AS_CONFED_SEQUENCE = 4
AS_PATH_SEG_STR = {AS_SET: 'set',
                   AS_SEQUENCE: 'sequence',
                   AS_CONFED_SET: 'confed_set',
                   AS_CONFED_SEQUENCE: 'confed_seq'}
AS_PATH_SEG_FORMAT = {AS_SET: '{ %s }',
                      AS_SEQUENCE: '%s',
                      AS_CONFED_SET: '( %s )',
                      AS_CONFED_SEQUENCE: '( %s )'}

# NOTIFICATION codes.
#
MESSAGE_HEADER_ERROR = 1
OPEN_MESSAGE_ERROR = 2
UPDATE_MESSAGE_ERROR = 3
HOLD_TIMER_EXPIRED = 4
FINITE_STATE_MACHINE_ERROR = 5
CEASE = 6
NOTIFICATION_STR = {MESSAGE_HEADER_ERROR: 'MESSAGE_HEADER_ERROR',
                    OPEN_MESSAGE_ERROR: 'OPEN_MESSAGE_ERROR',
                    UPDATE_MESSAGE_ERROR: 'UPDATE_MESSAGE_ERROR',
                    HOLD_TIMER_EXPIRED: 'HOLD_TIMER_EXPIRED',
                    FINITE_STATE_MACHINE_ERROR: 'FINITE_STATE_MACHINE_ERROR',
                    CEASE: 'CEASE'}

# Well-known community values.
#
WELL_KNOWN_COMM = {0xFFFFFF01: 'NO_EXPORT',
                   0xFFFFFF02: 'NO_ADVERTISE',
                   0xFFFFFF03: 'NO_EXPORT_SUBCONFED'}

# Address families, per RFC1700.
#
AF_IP = 1
AF_IP6 = 2
AF_STR = {AF_IP: 'IPv4',
          AF_IP6: 'IPv6'}

# Multiprotocol Subsequent Address Family Identifier (SAFI) per RFC2858.
#
MP_SAFI_STR = {1: 'unicast',
               2: 'multicast',
               3: 'unicast+multicast'}


# A function to determine the number of bytes necessary to represent a
# prefix of length 'len' per RFC4271.
#
def BytesForPrefix(prefix_len):
  """Determine the number of octets required to hold a prefix of length.

  Args:
    prefix_len: length of the prefix in bits.

  Returns:
    An int indicating how many octets are used to hold the prefix.

  Raises:
    ValueError: indicates that prefix_len has an invalid value
  """

  if prefix_len < 1 or prefix_len > 128:
    raise ValueError('prefix_len is out of range')
  return int(math.ceil(prefix_len / 8.0))


# A function to determine the number of bytes necessary to represent an
# SNPA of length 'len' per RFC2858.
#
def BytesForSnpa(snpa_len):
  """Determine the number of octets required to hold an SNPA.

  Args:
    snpa_len: length of the SNPA in semi-octets.

  Returns:
    An int indicating how many octets are used to hold the prefix.

  Raises:
    ValueError: indicates that snpa_len has an invalid value
  """

  # You have to read RFC2858 to believe this. SNPA lengths are expressed
  # in semi-octets.
  #
  if snpa_len < 1 or snpa_len > 256:
    raise ValueError('snpa_len is out of range')
  return int(math.ceil(snpa_len / 2.0))
