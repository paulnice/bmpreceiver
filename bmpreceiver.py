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
import BGP
import BMP
import indent

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

# Global variables specified here.
#
RECORD_SESSION = None
DEBUG_FLAG = 0


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
  indent_str = indent.IndentLevel(indent.BMP_CONTENT_INDENT)
  print_msg = []

  # Get the reason code for the peer down message, and decide what to
  # based on its value.
  #
  reason_code = CollectBytes(sock, 1)[0]
  if reason_code in BMP.PEER_DOWN_REASON_STR:
    print_msg.append("%s%s\n" % (indent_str,
                                 BMP.PEER_DOWN_REASON_STR[reason_code]))

    # If the BMP message contains a BGP NOTIFICATION message, collect 
    # and parse it.
    #
    if BMP.PeerDownHasBgpNotification(reason_code):

      # Collect and parse the BGP message header
      #
      header = CollectBytes(sock, BGP.HEADER_LEN)
      length, msg_type, msg_text = BGP.ParseBgpHeader(header, verbose=verbose)
      assert msg_type == BGP.NOTIFICATION
      print_msg.append("".join(msg_text))

      # collect and parse the BGP message body
      #
      notification = CollectBytes(sock, length)
      msg_text = BGP.ParseBgpNotification(notification, length, verbose=verbose)
      print_msg.append("".join(msg_text))

  elif DEBUG_FLAG:
    raise ValueError("Unknown BMP Peer Down reason %d" % reason_code)
  else:
    print_msg.append("Unknown BMP Peer Down reason %d\n" % reason_code)

  # Return list of strings representing collected message.
  #
  return print_msg


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
  indent_str = indent.IndentLevel(indent.BMP_CONTENT_INDENT)

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
    print_msg.append("%s%d %s\n" % (indent_str,
                                    stat_val,
                                    BMP.SR_TYPE_STR[stat_type]))

  # Return list of strings representing collected message.
  #
  return print_msg


def CollectBytes(sock, length):
  """Collect bytes from a stream socket or a file.

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
    buf = array.array("B")
    try:
      buf.read(sock, length)
    except EOFError:
      sock.close()
      sys.exit(0)
    if DEBUG_FLAG:
      print "READ %d BYTES FROM FILE" % len(buf)
      for x in range(length):
        print " %02x" % buf[x],

  # Done in either case; return the buffer that contains the requested
  # number of bytes.
  #
  return buf


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
  global RECORD_SESSION  # pylint: disable-msg=W0603
  global DEBUG_FLAG  # pylint: disable-msg=W0603

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
      raise ValueError("unhandled option")

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
      header = CollectBytes(conn, BMP.HEADER_LEN)
      msg_type, msg_text = BMP.ParseBmpHeader(header, verbose=verbose_flag)
      print "".join(msg_text),

      # Process the specific type of BMP message
      #
      # Route Monitoring message
      # draft-ietf-grow-bmp-01.txt section 2.1
      # The body of the message is a BGP UPDATE.
      #
      if msg_type == BMP.MSG_TYPE_ROUTE_MONITORING:

        # Collect and parse the BGP message header.
        #
        header = CollectBytes(conn, BGP.HEADER_LEN)
        length, msg_type, hdr_text = BGP.ParseBgpHeader(header,
                                                        verbose=verbose_flag)
        assert msg_type == BGP.UPDATE
        msg_text.append("".join(hdr_text))

        # Collect and parse the BGP message body.
        #
        update = CollectBytes(conn, length)
        try:
          msg_text = BGP.ParseBgpUpdate(update,
                                        length,
                                        rfc4893_updates=rfc4893_updates,
                                        verbose=verbose_flag)
        except Exception, esc:  # pylint: disable-msg=W0703
          print "Exception during ParseBgpUpdate: %s" % str(esc)

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
  except KeyboardInterrupt:
    sys.exit(0)
