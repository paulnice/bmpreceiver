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

"""A script implementing the receiver side BGP Monitoring Protocol (BMP).

This script can be invoked to receive data from a BMP sender (configured
to establish a connection to the receiver on port 20000):

    bmpreceiver.py --port=20000

It can record the sender's data stream to a file as it goes:

    bmpreceiver.py --port=20000 --file=bmp-data.bin

It can read from a data file by specifying a port number of 0:

    bmpreceiver.py --port=0 --file=bmp-data.bin
"""

__author__ = "sstuart@google.com (Stephen Stuart)"

import array
import getopt
import socket
import struct
import sys
import time
import BGP
import BMP

# Some of the acronyms found here:
# AFI - Address Family Identifier
# AS - Autonomous System
# NLRI - Network Layer Reachability Information
# PDU - Protocol Data Unit (a.k.a. "message")
# SAFI - Subsequent Address Family Identifier
# SNPA - SubNetwork Point of Attachment
# TLV - Type-Length-Value, a means of encoding information in a PDU

# Constants specified here.
#
HOST = ""
PORT = 0
INDENT_CHAR = " "
INDENT_COUNT = 2
BMP_HEADER_INDENT = 0
BMP_CONTENT_INDENT = 1
BGP_HEADER_INDENT = 1
BGP_CONTENT_INDENT = 2
BGP_MPATTR_INDENT = 3

# Global variables specified here.
#
RECORD_SESSION = None
DEBUG_FLAG = 0


# A function to collect the header of a BGP PDU, see RFC4271 section 4.1.
#
def CollectBgpHeader(sock, verbose=False):
  """Collect a BGP header.

  Args:
    sock: socket from which to read.
    verbose: be chatty, or not.

  Returns:
    An int indicating the length of the rest of the BGP message,
    an int indication the type of the message,
    a list of strings to print.
  """

  print_msg = []
  indent = IndentLevel(BGP_HEADER_INDENT)

  # Get the header.
  #
  header = CollectBytes(sock, BGP.HEADER_LEN)

  try:

    # Verify that the marker is correct, raise a ValueError exception if
    # it is not.
    #
    for x in range(0, 15):
      if header[x] != 255:
        raise ValueError("BGP marker octet %d != 255" % x)

    # Unpack the length and type.
    #
    length, msg_type = struct.unpack(">HB", header[16:19])
    if msg_type not in BGP.MSG_TYPE_STR:
      raise ValueError("BGP message type %d unknown" % msg_type)
    print_msg.append("%sBGP %s" % (indent, BGP.MSG_TYPE_STR[msg_type]))
    if verbose:
      print_msg.append(" length %d\n" % (length - BGP.HEADER_LEN))
    else:
      print_msg.append("\n")

    # Return the length of the rest of the PDU, its type, and the list
    # of strings representing the collected message
    #
    return length - BGP.HEADER_LEN, msg_type, print_msg

  # In case of any exception, dump the hex of the message to help
  # debug what's wrong with the message, and re-raise the exception.
  #
  except Exception, esc:
    hex_dump = []
    for x in range(BGP.HEADER_LEN):
      hex_dump.append("0x%x" % struct.unpack("B", header[x]))
    print " ".join(hex_dump)
    raise esc


# A function to collect a BGP notification message, see RFC4271 section 4.5.
#
def CollectBgpNotification(sock, verbose=False):
  """Collect a BGP Notification message.

  Args:
    sock: socket from which to read.
    verbose: be chatty, or not.

  Returns:
    A list of strings to print
  """

  print_msg = []
  indent = IndentLevel(BGP_CONTENT_INDENT)

  # Get the header.
  #
  length, msg_type, msg_text = CollectBgpHeader(sock)
  assert msg_type == BGP.NOTIFICATION
  print_msg.append("".join(msg_text))

  # Get the rest of the message.
  #
  notification = CollectBytes(sock, length)
  code, subcode = struct.unpack(">BB", notification[0:2])
  print_msg.append("%sNOTIFICATION code %d subcode %d\n" % (indent,
                                                            code,
                                                            subcode))

  # If there are data bytes, convert them to text as hex digits.
  #
  if length > 2 and verbose:
    print_msg.append("%sNOTIFICATION data " % indent)
    for x in range(3, length - 1):
      print_msg.append(" 0x%x" % notification[x])
    print_msg.append("\n")

  # Return the list of strings representing collected message.
  #
  return print_msg


# A function to collect a BGP update PDU, see:
# RFC1997
# RFC2858
# RFC4271 section 4.3
# RFC4893
#
def CollectBgpUpdate(sock, rfc4893_updates=False, verbose=False):
  """Collect a BGP Update message.

  Args:
    sock: socket from which to read.
    rfc4893_updates: true if update conforms to RFC4893
    verbose: be chatty, or not.

  Returns:
    A list of strings to print

  Raises:
    ValueError: an unexpected value was found in the message
  """

  print_msg = []
  indent = IndentLevel(BGP_CONTENT_INDENT)

  # Get the header.
  #
  length, msg_type, msg_text = CollectBgpHeader(sock, verbose=verbose)
  assert msg_type == BGP.UPDATE
  print_msg.append("".join(msg_text))

  # Get the rest of the message.
  #
  update = CollectBytes(sock, length)

  # Start parsing at offset 0.
  #
  offset = 0

  # Next section is withdrawn routes.
  #
  withdrawn_route_len = struct.unpack_from(">H", update[0:2], offset)[0]
  if verbose:
    print_msg.append("%swithdrawn at %d length %d\n" % (indent,
                                                        offset,
                                                        withdrawn_route_len))
  offset += 2

  # If any withdrawn routes are present, process them.
  #
  if withdrawn_route_len:
    withdrawn_text = ParseBgpNlri(update,
                                  offset,
                                  offset + withdrawn_route_len,
                                  BGP.AF_IP)
    if withdrawn_text:
      prepend_str = "%swithdraw " % indent
      sep = "\n%s" % prepend_str
      print_msg.append("%s%s\n" % (prepend_str, sep.join(withdrawn_text)))

    offset += withdrawn_route_len

  # Next section is path attributes
  #
  path_attr_len = struct.unpack_from(">H", update, offset)[0]
  if verbose:
    print_msg.append("%spath attributes at %d length %d\n" % (indent,
                                                              offset,
                                                              path_attr_len))
  offset += 2

  # If there are path attributes present, process them.
  #
  path_attr_end = offset + path_attr_len
  while offset < path_attr_end:

    # Get flags and type code.
    #
    attr_flags, attr_type = struct.unpack_from(">BB", update, offset)

    # If we're being verbose, describe the details of the path attribute.
    # We haven't updated offset yet in order to be able to report the
    # offset of the path attribute section in the verbose text.
    #
    if verbose:
      print_msg.append("%spath attr %s at %d" % (indent,
                                                 BGP.ATTR_TYPE_STR[attr_type],
                                                 offset))
      print_msg.append(" flags 0x%x (" % attr_flags)
      attr_list = []
      if (attr_flags & BGP.ATTR_FLAG_OPTIONAL) == BGP.ATTR_FLAG_OPTIONAL:
        attr_list.append("optional")
      if (attr_flags & BGP.ATTR_FLAG_TRANSITIVE) == BGP.ATTR_FLAG_TRANSITIVE:
        attr_list.append("transitive")
      if (attr_flags & BGP.ATTR_FLAG_PARTIAL) == BGP.ATTR_FLAG_PARTIAL:
        attr_list.append("partial")
      if (attr_flags & BGP.ATTR_FLAG_EXT_LEN) == BGP.ATTR_FLAG_EXT_LEN:
        attr_list.append("extended-length")
      print_msg.append(" ".join(attr_list))

    # Now increment the offset, check for extended length, and get the
    # length (whose size depends on the extended length flag).
    #
    offset += 2
    if (attr_flags & BGP.ATTR_FLAG_EXT_LEN) == BGP.ATTR_FLAG_EXT_LEN:
      attr_len = struct.unpack_from(">H", update, offset)[0]
      offset += 2
    else:
      attr_len = update[offset]
      offset += 1

    # Finish up the verbose processing of the path attribute's details.
    #
    if verbose:
      print_msg.append(") len %d\n" % attr_len)

    # Now we can process the specific types of path attribute, see:
    # RFC4271
    # RFC2858
    #
    # ORIGIN
    #
    if attr_type == BGP.ATTR_TYPE_ORIGIN:

      # we know both length and possible values of the ORIGIN attribute,
      # raise a ValueError exception if we find something unexpected
      #
      if attr_len != 1:
        raise ValueError("BGP ORIGIN attr_len %d wrong, expected 1" % attr_len)
      if update[offset] not in BGP.ORIGIN_STR:
        raise ValueError("BGP ORIGIN value %d wrong" % update[offset])
      print_msg.append("%s%s %s\n" % (indent,
                                      BGP.ATTR_TYPE_STR[attr_type],
                                      BGP.ORIGIN_STR[update[offset]]))

    # AS_PATH (Autonomous System path)
    #
    elif attr_type == BGP.ATTR_TYPE_AS_PATH:
      print_msg.append("%s%s " % (indent, BGP.ATTR_TYPE_STR[attr_type]))
      path_text = ParseBgpAsPath(update,
                                 offset,
                                 offset + attr_len,
                                 rfc4893_updates)
      print_msg.append("%s\n" % " ".join(path_text))

    # NEXT_HOP
    #
    elif attr_type == BGP.ATTR_TYPE_NEXT_HOP:
      next_hop = update[offset:offset + 4]
      print_msg.append("%s%s %s\n" % (indent,
                                      BGP.ATTR_TYPE_STR[attr_type],
                                      socket.inet_ntoa(next_hop)))

    # MED (Multi-Exit Discriminator)
    #
    elif attr_type == BGP.ATTR_TYPE_MULTI_EXIT_DISC:
      med_val = struct.unpack_from(">L", update, offset)[0]
      print_msg.append("%s%s %d\n" % (indent,
                                      BGP.ATTR_TYPE_STR[attr_type],
                                      med_val))

    # COMMUNITIES
    #
    elif attr_type == BGP.ATTR_TYPE_COMMUNITIES:
      print_msg.append("%s%s " % (indent, BGP.ATTR_TYPE_STR[attr_type]))
      comm_text = ParseBgpCommunities(update, offset, offset + attr_len)
      print_msg.append("%s\n" % " ".join(comm_text))

    # MP_REACH
    #
    elif attr_type == BGP.ATTR_TYPE_MP_REACH_NLRI:
      print_msg.append("%s%s\n" % (indent, BGP.ATTR_TYPE_STR[attr_type]))
      mpattr_text = ParseBgpMpAttr(update, offset, offset + attr_len, True)
      mp_indent = IndentLevel(BGP_MPATTR_INDENT)
      for mpattr in mpattr_text:
        print_msg.append("%s%s" % (mp_indent, mpattr))

    # MP_UNREACH
    #
    elif attr_type == BGP.ATTR_TYPE_MP_UNREACH_NLRI:
      print_msg.append("%s%s\n" % (indent, BGP.ATTR_TYPE_STR[attr_type]))
      mpattr_text = ParseBgpMpAttr(update, offset, offset + attr_len, False)
      mp_indent = IndentLevel(BGP_MPATTR_INDENT)
      for mpattr in mpattr_text:
        print_msg.append("%s%s" % (mp_indent, mpattr))

    # Here we have a catch-all for attributes that we don't parse out
    # in detail (yet) - one for when we have a text representation
    # for the type code, and finally one for when we don't.
    #
    elif attr_type in BGP.ATTR_TYPE_STR:
      print_msg.append("%s%s\n" % (indent, BGP.ATTR_TYPE_STR[attr_type]))
    else:
      print_msg.append("%sBGP path attrbute type %d\n" % (indent, attr_type))

    # adjust the offset past the path attributes
    #
    offset += attr_len

  # Next section is prefixes reachable according to what's in the path
  # attributes section, parse and add to print_msg.
  #
  if verbose:
    print_msg.append("%sNLRI portion of update at %d\n" % (indent, offset))
  nlri_text = ParseBgpNlri(update, offset, length, BGP.AF_IP)
  if nlri_text:
    prepend_str = "%snlri " % indent
    sep = "\n%s" % prepend_str
    print_msg.append("%s%s\n" % (prepend_str, sep.join(nlri_text)))

  # Return list of strings representing collected message.
  #
  return print_msg


# A function to collect a BMP header.
#
def CollectBmpHeader(sock, verbose=False):
  """Collect a BMP header.

  Args:
    sock: socket from which to read.
    verbose: be chatty, or not.

  Returns:
    An int indicating the type of message that follows the header,
    and a list of strings to print.

  Raises:
    ValueError: an unexpected value was found in the message
  """

  # Initialize.
  #
  indent = IndentLevel(BMP_HEADER_INDENT)
  print_msg = []

  # Read the fixed-length header from the socket.
  #
  header = CollectBytes(sock, BMP.HEADER_LEN)

  # Unpack and decide what to print.
  #
  version, msg_type, peer_type, peer_flags = struct.unpack(">BBBB",
                                                           header[0:4])
  print_msg.append("%sBMP version %d type %s" % (indent,
                                                 version,
                                                 BMP.MSG_TYPE_STR[msg_type]))
  if verbose:
    print_msg.append(" peer_type %s" % BMP.PEER_TYPE_STR[peer_type])
    print_msg.append(" peer_flags 0x%x\n" % peer_flags)
  else:
    print_msg.append("\n")
  if peer_flags & BMP.PEER_FLAG_IPV6:
    peer_address = socket.inet_ntop(socket.AF_INET6, header[12:28])
  else:
    peer_address = socket.inet_ntop(socket.AF_INET, header[24:28])
  if verbose:
    print_msg.append("%speer_address %s" % (indent, peer_address))
    peer_as, time_sec = struct.unpack(">LxxxxL",
                                      header[28:40])
    print_msg.append(" as %d" % peer_as)
    print_msg.append(" router_id %s\n" % socket.inet_ntoa(header[32:36]))
    print_msg.append("%stime %s\n" % (indent, time.ctime(time_sec)))

  # If we have a version mismatch, we're pretty much done here.
  #
  if version != BMP.VERSION:
    raise ValueError("Found BMP version %d, expecting %d" % (version,
                                                             BMP.VERSION))

  # Return the message type so the caller can decide what to do next,
  # and the list of strings representing the collected message.
  #
  return msg_type, print_msg


# A function to collect a BMP peer down notification.
#
def CollectBmpPeerDown(sock, verbose=False):
  """Collect a BMP Peer Down message.

  Args:
    sock: socket from which to read.
    verbose: be chatty, or not.

  Returns:
    nothing

  Raises:
    ValueError: an unexpected value was found in the message
  """

  # Initialize.
  #
  indent = IndentLevel(BMP_CONTENT_INDENT)
  print_msg = []

  # Get the reason code for the peer down message, and decide what to
  # based on its value.
  #
  reason_code = CollectBytes(sock, 1)[0]
  if reason_code in BMP.PEER_DOWN_REASON_STR:
    print_msg.append("%s%s\n" % (indent,
                                 BMP.PEER_DOWN_REASON_STR[reason_code]))
    if BMP.PeerDownHasBgpNotification(reason_code):
      msg_text = CollectBgpNotification(sock, verbose=verbose)
      print_msg.append("".join(msg_text))
  elif DEBUG_FLAG:
    raise ValueError("Unknown BMP Peer Down reason %d" % reason_code)
  else:
    print_msg.append("Unknown BMP Peer Down reason %d\n" % reason_code)

  # Return list of strings representing collected message.
  #
  return print_msg


# A function to collect a BMP statistics report.
#
def CollectBmpStatsMsg(sock):
  """Collect a BMP Statistics Report message.

  Args:
    sock: socket from which to read.

  Returns:
    A list of strings.
  """

  # Initialize.
  #
  print_msg = []
  indent = IndentLevel(BMP_CONTENT_INDENT)

  # Find out many TLVs (Type-Length-Value) there are in the message.
  #
  stats_count_buf = CollectBytes(sock, 4)
  stats_count = struct.unpack(">L", stats_count_buf)[0]

  # Read all the TLVs.
  #
  for _ in xrange(stats_count):

    # Get the type and the length.
    #
    stat_type_len_buf = CollectBytes(sock, 4)
    stat_type, stat_len = struct.unpack(">HH", stat_type_len_buf)

    # All the values in the spec so far are type long, length == 4.
    #
    assert stat_type in BMP.SR_TYPE_STR
    assert stat_len == 4
    stat_val_buf = CollectBytes(sock, stat_len)
    stat_val = struct.unpack(">L", stat_val_buf)[0]
    print_msg.append("%s%d %s\n" % (indent,
                                    stat_val,
                                    BMP.SR_TYPE_STR[stat_type]))

  # Return list of strings representing collected message.
  #
  return print_msg


# A function to collect bytes from a stream socket *or* a file.
#
def CollectBytes(sock, length):
  """Collect bytes from a socket or file.

  Args:
    sock: socket from which to read.
    length: number of bytes to read.

  Returns:
    a buffer containing the requested number of bytes
  """

  # If it's a socket, do this:
  #
  if type(sock) == socket.SocketType:

    # Read length bytes from the socket into the right sized buffer.
    #
    buf = array.array("B", [0] * length)
    remain = length

    while remain:
      count = sock.recv_into(buf, remain)
      remain -= count

      # Maybe write to the recording session.
      #
      if RECORD_SESSION is not None:
        RECORD_SESSION.write(buf)
        RECORD_SESSION.flush()

  # If it's not a socket, do this:
  #
  else:
    string_val = sock.read(length)
    if len(string_val) < length:
      sock.close()
      sys.exit(0)
    buf = array.array("B", [0] * length)
    for x in range(length):
      struct.pack_into("B",
                       buf,
                       x,
                       struct.unpack_from("B", string_val, x)[0])

  # Return the buffer.
  #
  return buf


# Return a string of spaces at the requested indentation level.
#
def IndentLevel(level):
  """Return a string of spaces at the requested indentation level.

  Args:
    level: int indicating indentation level (0 == no leading spaces)

  Returns:
    A string of spaces.
  """

  return INDENT_CHAR * INDENT_COUNT * level


# A function to parse BGP AS_PATH path attribute information.
#
def ParseBgpAsPath(update, start, end, rfc4893_updates):
  """Parse BGP AS Path information into readable text per RFC4271.

  Args:
    update: a buffer containing a BGP message.
    start: offset at which AS Path parsing is to start.
    end: offset at which AS Path parsing is to stop.
    rfc4893_updates: true if AS Path conforms to RFC4893, otherwise false

  Returns:
    A list of strings.
  """

  # Initialize.
  #
  path_text = []

  # We're going to try this with the default value of rfc4893_updates,
  # and try again with it forced to True if we get an exception.
  #
  try:

    # Start at the beginning ...
    #
    offset = start

    # Walk through the path segments.
    #
    while offset < end:

      # Get type and length.
      #
      path_seg_type = update[offset]
      offset += 1
      path_seg_len = update[offset]
      offset += 1
      path_seg_val = []

      # Step through AS numbers in path.
      #
      for _ in range(path_seg_len):

        # RFC4893-style updates have 4-octet ASNs, otherwise 2-octet ASNs.
        #
        if rfc4893_updates:
          path_seg_val.append(str(struct.unpack_from(">L",
                                                     update,
                                                     offset)[0]))
          offset += 4
        else:
          path_seg_val.append(str(struct.unpack_from(">H",
                                                     update,
                                                     offset)[0]))
          offset += 2

      # Turn the list of AS numbers into text, using a format string
      # appropriate to the segment type.
      #
      path_seg_str = " ".join(path_seg_val)
      path_text.append(BGP.AS_PATH_SEG_FORMAT[path_seg_type] % path_seg_str)
      path_text.append("\n")

  # If we get a KeyError exception and the rfc4893_updates flag is not
  # set, try again with rfc4893_updates set; else reraise the exception.
  #
  except KeyError, esc:
    if not rfc4893_updates:
      Warn(["ParseBgpAsPath setting --rfc4893_updates due to parsing error"])
      rfc4893_updates += 1
      path_text = []
    else:
      raise esc

  # Return the list of strings.
  #
  return path_text


# A function to parse BGP COMMUNITIES path attribute information.
#
def ParseBgpCommunities(update, start, end):
  """Parse BGP community information into readable text.

  Args:
    update: a buffer containing a BGP message.
    start: offset at which community parsing is to start.
    end: offset at which community parsing is to stop.

  Returns:
    a list of strings
  """

  # Initialize.
  #
  comm_text = []
  offset = start

  # Walk through the community values.
  #
  while offset < end:

    # Get a value.
    #
    x = struct.unpack_from(">L", update, offset)[0]

    # If a well-known community, use its name; else unpack it again for
    # presentation.
    #
    if x in BGP.WELL_KNOWN_COMM:
      comm_text.append(BGP.WELL_KNOWN_COMM[x])
    else:
      high, low = struct.unpack_from(">HH", update, offset)
      comm_text.append("%d:%d" % (high, low))

    # On to the next.
    #
    offset += 4

  # Return the list of strings.
  #
  return comm_text


# A function to parse BGP MP_REACH or MP_UNREACH path attribute information.
#
def ParseBgpMpAttr(update, start, end, has_snpa):
  """Parse a BGP MP_REACH or MP_UNREACH attribute into readable text.

  Args:
    update: a buffer containing a BGP message.
    start: offset at which attribute parsing is to start.
    end: offset at which attribute parsing is to stop.
    has_snpa: True if there's an SNPA section, False otherwise

  Returns:
    A list of strings.
  """

  # Initialize.
  #
  mpattr_text = []
  offset = start

  # Start with AFI, SAFI, length of next hop.
  #
  afi, safi, nhl = struct.unpack_from(">HBB", update, offset)
  offset += 4

  # NEXT_HOP depends on length of next hop.
  #
  unused_socket_afi = 0
  if afi == BGP.AF_IP:
    unused_socket_afi = socket.AF_INET
    next_hop = socket.inet_ntop(socket.AF_INET, update[offset:offset+4])
  elif afi == BGP.AF_IP6:
    unused_socket_afi = socket.AF_INET6
    next_hop = socket.inet_ntop(socket.AF_INET6,
                                update[offset:offset+16])
  else:
    next_hop = "unknown for afi %d" % afi
  mpattr_text.append("NEXT_HOP %s\n" % next_hop)

  # Turn AFI, SAFI into text.
  #
  if afi in BGP.AF_STR:
    afi_str = BGP.AF_STR[afi]
  else:
    afi_str = str(afi)
  if safi in BGP.MP_SAFI_STR:
    safi_str = BGP.MP_SAFI_STR[safi]
  else:
    safi_str = str(safi)
  mpattr_text.append("AFI %s SAFI %s\n" % (afi_str, safi_str))

  # On to the next.
  #
  offset += nhl

  # Next might be SNPA.
  #
  if has_snpa:

    # Unpack the number of SNPAs.
    #
    num_snpa = struct.unpack_from(">B", update, offset)[0]
    offset += 1

    # Dump the SNPAs as hex.
    #
    for _ in range(num_snpa):

      # Get the length.
      #
      snpa_len = struct.unpack_from(">B", update, offset)[0]
      offset += 1

      # You have to read RFC2858 to believe this.
      #
      snpa_len_octets = BGP.BytesForSnpa(snpa_len)
      snpa_dump = []
      for y in range(snpa_len_octets):
        snpa_dump.append("0x%x" % struct.unpack_from(">B",
                                                     update,
                                                     offset + y))
      mpattr_text.append("SNPA %s\n" % " ".join(snpa_dump))
      offset += snpa_len_octets

  # Next section is NLRI information.
  #
  nlri_text = ParseBgpNlri(update, offset, end, afi)
  for nlri_str in nlri_text:
    mpattr_text.append("mp_nlri %s\n" % nlri_str)

  # Return list of strings.
  #
  return mpattr_text


# A function to parse BGP NLRI information.
#
def ParseBgpNlri(update, start, end, afi):
  """Parse BGP NLRI into readable text.

  Args:
    update: a buffer containing a BGP message.
    start: offset at which NLRI parsing is to start.
    end: offset at which NLRI parsing is to stop.
    afi: address family, per RFC1700.

  Returns:
    A list of strings.
  """

  # Initialize.
  #
  nlri_text = []
  offset = start

  # While there's data left to parse ...
  #
  while offset < end:

    # Get prefix length, and figure out how much we need to take from
    # update to represent it.
    #
    prefix_len = update[offset]
    need_bytes = BGP.BytesForPrefix(prefix_len)
    offset += 1

    # Override AFI if it's AF_IP and we know that the number of octets
    # necessary to hold the NLRI is more than is valid for AF_IP. This
    # is done because it appears that JUNOS 9.5 sends AF_IP6 withdraws
    # in the regular withdraw section of a BGP UPDATE message, rather
    # than constructing an MP_UNREACH path attribute and putting the
    # AF_IP6 withdraws there.
    #
    if (need_bytes > 4) and (afi == BGP.AF_IP):
      Warn(["ParseBgpNlri overriding AFI due to bytes needed for",
            " prefix length"])
      afi = BGP.AF_IP6

    # Get a buffer of correct size for address family, and pick the
    # right AFI for the socket library (which varies from platform to
    # platform and does not correspond to the RFC1700 values for AFI).
    #
    if afi == BGP.AF_IP:
      socket_afi = socket.AF_INET
      prefix = array.array("B", [0] * 4)
    elif afi == BGP.AF_IP6:
      socket_afi = socket.AF_INET6
      prefix = array.array("B", [0] * 16)
    else:
      assert False, "don't know what to do with AFI %d" % afi

    # Copy from update into buffer and advance pointer.
    #
    for x in range(need_bytes):
      prefix[x] = update[x + offset]
    offset += need_bytes

    # Convert to presentation.
    #
    nlri_text.append("%s/%d" % (socket.inet_ntop(socket_afi, prefix),
                                prefix_len))

  # Return list of strings.
  #
  return nlri_text


# A function to print usage information.
#
def Usage():
  """Print usage information.

  Args:
    none.

  Returns:
    nothing
  """

  print """
Usage: bmpreceiver.py [-d | --debug]
                      [-v | --verbose]
                      [-4 | --rfc4893]
                      [-f file | --file=file]
                      [-p port | --port=port]
Options:
  -d      : print debug messages
  -v      : print verbose messages
  -4      : RFC4893-style BGP updates
  -f file : if port > 0, record BMP messages to file
          : if port = 0, read BMP messages from file
  -p port : if port > 0, port on which to listen for a BMP connection
          : if port = 0, read BMP messages from file specified in -f
"""


# A function to print a message to stderr.
#
def Warn(message):
  """Print a warning message to stderr.

  Args:
    message: a list of strings to write to stderr.

  Returns:
    nothing
  """

  if DEBUG_FLAG:
    sys.stderr.write("WARNING: %s\n" % "".join(message))


# main
#
def main(argv):
  global RECORD_SESSION
  global DEBUG_FLAG

  # Process command-line arguments.
  #
  try:
    opts, args = getopt.getopt(argv,
                               "dv4p:f:",
                               ["debug",
                                "verbose",
                                "rfc4893",
                                "port=",
                                "file="])
  except getopt.GetoptError:
    Usage()
    sys.exit(2)

  if args:
    Usage()
    sys.exit(2)

  port = PORT
  rfc4893_updates = False
  verbose_flag = False
  record_file = ""
  for o, a in opts:
    if o in ("-p", "--port"):
      port = int(a)
    elif o in ("-f", "--file"):
      record_file = a
    elif o in ("-4", "--rfc4893"):
      rfc4893_updates = True
    elif o in ("-d", "--debug"):
      DEBUG_FLAG += 1
    elif o in ("-v", "--verbose"):
      verbose_flag = True
    else:
      assert False, "unhandled option"

  # If recording, open the file for write.
  #
  if port and record_file:
    try:
      RECORD_SESSION = open(record_file, "wb")
    except Exception:
      raise Exception("error opening %s for write" % record_file)
  else:
    RECORD_SESSION = None

  # If port is non-zero open a listening socket, wait for a connection.
  #
  if port != 0:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((HOST, port))
    listener.listen(1)

  # We have either a connection from a BMP sender, or a file from which
  # to read; we want to loop over connections, if we're reading from a
  # file an exit will take place on EOF.
  #
  while True:

    # If port is non-zero, we got a connection; accept it.
    #
    if port != 0:
      conn, addr = listener.accept()
      print "Connection from %s port %d" % (addr[0], addr[1])
    else:
      conn = open(record_file, "rb", 0)
      print "Reading from file %s" % record_file

    # Loop over either the data stream from the socket, or the contents
    # of a file.
    #
    while True:

      # Read a BMP header.
      #
      msg_type, msg_text = CollectBmpHeader(conn, verbose=verbose_flag)
      print "".join(msg_text),

      # Process the specific type of BMP message
      #
      # Route Monitoring message
      # draft-ietf-grow-bmp-01.txt section 2.1
      #
      if msg_type == BMP.MSG_TYPE_ROUTE_MONITORING:
        msg_text = CollectBgpUpdate(conn,
                                    rfc4893_updates=rfc4893_updates,
                                    verbose=verbose_flag)

      # Statistics Report
      # draft-ietf-grow-bmp-01.txt section 2.2
      #
      elif msg_type == BMP.MSG_TYPE_STATISTICS_REPORT:
        msg_text = CollectBmpStatsMsg(conn)

      # Peer Down message
      # draft-ietf-grow-bmp-01.txt section 2.3
      #
      elif msg_type == BMP.MSG_TYPE_PEER_DOWN_NOTIFICATION:
        msg_text = CollectBmpPeerDown(conn, verbose=verbose_flag)

      # else we don't know the type, we can't parse any more; raise
      # a ValueError exception if we're debugging, else just squawk
      #
      elif DEBUG_FLAG:
        raise ValueError("unknown BMP message type %d" % msg_type)
      else:
        msg_text = "unknown BMP message type %d\n" % msg_type

      # If there's anything to print, print.
      #
      if msg_text:
        print "".join(msg_text),


# Call main with args; if a file was opened, close it.
#
if __name__ == "__main__":
  try:
    main(sys.argv[1:])
  finally:
    if RECORD_SESSION is not None:
      RECORD_SESSION.close()
