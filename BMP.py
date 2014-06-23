#!/usr/bin/python2.5  # pylint: disable-msg=C6301,C6409
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

"""BGP Monitoring Protocol - various constants."""

__author__ = "sstuart@google.com (Stephen Stuart)"
__version__ = "0.1"

import socket
import struct
import time
import indent
import re

# The length of the version field that starts every BMP message.
#
VERSION_LEN = 1

# The length of the fixed header part of a BMP message.
#
HEADER_LEN_V1 = 44
HEADER_LEN_V3 = 6
PER_PEER_HEADER_LEN_V3 = 42

# various message lengths
#
PEER_UP_LEN = 20

# Version of the protocol, as specified in the header.
#
VERSION_MIN = 1
VERSION_MAX = 3

# Message types.
#
MSG_TYPE_ROUTE_MONITORING = 0
MSG_TYPE_STATISTICS_REPORT = 1
MSG_TYPE_PEER_DOWN_NOTIFICATION = 2
MSG_TYPE_PEER_UP_NOTIFICATION = 3
MSG_TYPE_INITIATION_MESSAGE = 4
MSG_TYPE_TERMINATION_MESSAGE = 5
MSG_TYPE_STR = {MSG_TYPE_ROUTE_MONITORING: "Route Monitoring",
                MSG_TYPE_STATISTICS_REPORT: "Statistics Report",
                MSG_TYPE_PEER_DOWN_NOTIFICATION: "Peer Down Notification",
                MSG_TYPE_PEER_UP_NOTIFICATION: "Peer Up Notification",
                MSG_TYPE_INITIATION_MESSAGE: "Initiation Message",
                MSG_TYPE_TERMINATION_MESSAGE: "Termination Message"}

# Initiation message information types
#
INIT_INFO_TYPE_STRING = 0
INIT_INFO_TYPE_SYSDESCR = 1
INIT_INFO_TYPE_SYSNAME = 2
INIT_INFO_TYPE_STR = {INIT_INFO_TYPE_STRING: "String",
                      INIT_INFO_TYPE_SYSDESCR: "sysDescr",
                      INIT_INFO_TYPE_SYSNAME: "sysName"}

# Peer types.
#
PEER_TYPE_GLOBAL = 0
PEER_TYPE_L3_VPN = 1
PEER_TYPE_STR = {PEER_TYPE_GLOBAL: "Global",
                 PEER_TYPE_L3_VPN: "L3 VPN"}

# Peer flags.
#
PEER_FLAG_IPV6 = 0x80

# Statistics report type codes.
#
SR_TYPE_STR = {0: "prefixes rejected by inbound policy",
               1: "(known) duplicate prefix advertisements",
               2: "(known) duplicate withdraws",
               3: "updates invalidated due to CLUSTER_LIST loop",
               4: "updates invalidated due to AS_PATH loop",
               5: "updates invalidated due to ORIGINATOR_ID",
               6: "updates invalidated due to AS_CONFED loop",
               7: "routes in Adj-RIBs-In",
               8: "routes in Loc-RIB"}

# Peer down reason codes.
#
PEER_DOWN_REASON_STR = {1: "Local system closed session, notification sent",
                        2: "Local system closed session, no notification",
                        3: "Remote system closed session, notification sent",
                        4: "Remote system closed session, no notification"}


def ParseBmpHeaderV1(header, verbose=False):
  """Parse a BMP V1 header.

  Args:
    header: array containing BMP message header.
    verbose: be chatty, or not.

  Returns:
    An int indicating the type of message that follows the header,
    and a list of strings to print.

  Raises:
    ValueError: an unexpected value was found in the message
  """

  indent_str = indent.IndentLevel(indent.BMP_HEADER_INDENT)
  print_msg = []

  version = 1
  msg_type, peer_type, peer_flags = struct.unpack(">BBB",
                                                  header[0:3])
  if peer_flags & PEER_FLAG_IPV6:
    peer_address = socket.inet_ntop(socket.AF_INET6, header[11:27])
  else:
    peer_address = socket.inet_ntop(socket.AF_INET, header[23:27])
  peer_as, time_sec = struct.unpack(">LxxxxL",
                                    header[27:39])

  # If we have a version mismatch, we're pretty much done here.
  #
  if version != 1:
    raise ValueError("Found BMP version %d, expecting %d" % (version, 1))

  # Decide what to format as text
  #
  print_msg.append("%sBMP version %d type %s peer %s AS %d\n" %
                   (indent_str,
                    version,
                    MSG_TYPE_STR[msg_type],
                    peer_address,
                    peer_as))
  if verbose:
    print_msg.append("%speer_type %s" % (indent_str,
                                         PEER_TYPE_STR[peer_type]))
    print_msg.append(" peer_flags 0x%x" % peer_flags)
    print_msg.append(" router_id %s\n" % socket.inet_ntoa(header[31:34]))
    print_msg.append("%stime %s\n" % (indent_str, time.ctime(time_sec)))

  # Return the message type so the caller can decide what to do next,
  # and the list of strings representing the collected message.
  #
  return msg_type, print_msg


def ParseBmpHeaderV3(header, verbose=False):
  """Parse a BMP V3 header.

  Args:
    header: array containing BMP message header.
    verbose: be chatty, or not.

  Returns:
    An int indicating the type of message that follows the header,
    and a list of strings to print.

  Raises:
    ValueError: an unexpected value was found in the message
  """

  indent_str = indent.IndentLevel(indent.BMP_HEADER_INDENT)
  print_msg = []

  version = 3
  msg_length = struct.unpack(">L", header[0:4])
  msg_type = header[4];

  # Decide what to format as text
  #
  print_msg.append("%sBMP version %d type %s length %d\n" %
                   (indent_str,
                    version,
                    MSG_TYPE_STR[msg_type],
                    msg_length[0]))

  # Return the message type so the caller can decide what to do next,
  # and the list of strings representing the collected message.
  #
  return msg_type, msg_length[0], print_msg


def ParseBmpPeerUp(message, peer_flags, verbose=False):
  """Parse a BMP V3 Peer Up message.

  Args:
    header: array containing BMP peer up message.
    peer_flags: from the per-peer header.
    verbose: be chatty, or not.

  Returns:
    A list of strings to print.

  Raises:
    ValueError: an unexpected value was found in the message
  """

  indent_str = indent.IndentLevel(indent.BMP_CONTENT_INDENT)
  print_msg = []
  offset = 0

  if peer_flags & PEER_FLAG_IPV6:
    loc_addr = socket.inet_ntop(socket.AF_INET6, 
                                message[offset : offset + 16])
  else:
    loc_addr = socket.inet_ntop(socket.AF_INET, 
                                message[offset + 12 : offset + 16])
  offset += 16
  loc_port, rem_port = struct.unpack_from(">HH", message, offset)

  print_msg.append("%sloc_addr %s, loc_port %d, rem_port %d\n" % (indent_str,
                                                                  loc_addr,
                                                                  loc_port,
                                                                  rem_port))
  return print_msg


def ParseBmpPerPeerHeaderV3(header, verbose=False):
  """Parse a BMP V3 per-peer header.

  Args:
    header: array containing BMP message header.
    verbose: be chatty, or not.

  Returns:
    An int indicating the peer flags
    and a list of strings to print.

  Raises:
    ValueError: an unexpected value was found in the message
  """

  indent_str = indent.IndentLevel(indent.BMP_CONTENT_INDENT)
  print_msg = []
  offset = 0

  # peer type, flags, and the rest
  #
  peer_type, peer_flags = struct.unpack_from(">BB", header, offset)
  offset += 2
  peer_dist = struct.unpack_from("8B", header, offset)
  offset += 8
  if peer_flags & PEER_FLAG_IPV6:
    peer_address = socket.inet_ntop(socket.AF_INET6, 
                                    header[offset : offset + 16])
  else:
    peer_address = socket.inet_ntop(socket.AF_INET, 
                                    header[offset + 12 : offset + 16])
  offset += 16
  peer_as, peer_bgp_id, time_sec, time_usec = struct.unpack_from(">LLLL",
                                                                 header,
                                                                 offset)

  # Decide what to format as text
  #
  print_msg.append("%sPeer Type %s, flags %d, address %s, AS %d\n" %
                   (indent_str,
                    PEER_TYPE_STR[peer_type],
                    peer_flags,
                    peer_address,
                    peer_as))
  time_str = time.strftime("%Y-%m-%d %H:%M", time.gmtime(time_sec))
  time_frac = time_usec / 1000000.0
  
  print_msg.append("%sTime %s.%s\n" % 
                   (indent_str, time_str, re.split('\.', str(time_frac))[1]))

  # Return the message type so the caller can decide what to do next,
  # and the list of strings representing the collected message.
  #
  return peer_flags, print_msg


# A function indication whether or not a BMP Peer Down message comes
# with a BGP notification
#
def PeerDownHasBgpNotification(reason):
  """Determine whether or not a BMP Peer Down message as a BGP notification.

  Args:
    reason: the Peer Down reason code (from the draft)

  Returns:
    True if there will be a BGP Notification, False if not
  """

  return reason == 1 or reason == 3
