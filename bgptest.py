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

"""A script to test bmpreciever.py."""

import array
import struct
import BGP


def TestBgpHeader():
  """BGP message header related tests."""

  buf = array.array("B", [0] * BGP.HEADER_LEN)

  # pretend it's an update
  #
  struct.pack_into(">HB", buf, 16, BGP.HEADER_LEN, BGP.UPDATE)

  # invalid marker at position 'y'
  #
  for y in range(0, 16):
    for x in range(0, 16):
      if x == y:
        buf[x] = 127
      else:
        buf[x] = 255
    try:
      BGP.ParseBgpHeader(buf, verbose=False)
    except ValueError:
      print "marker incorrect - ParseBgpHeader raised ValueError"

  # correct the marker for further tests
  #
  for x in range(0, 16):
    buf[x] = 255

  # try setting invalid lengths (too small, too large)
  #
  struct.pack_into(">HB", buf, 16, BGP.MIN_LENGTH - 1, BGP.UPDATE)
  try:
    BGP.ParseBgpHeader(buf, verbose=False)
  except ValueError:
    print "packet too short - ParseBgpHeader raised ValueError"

  struct.pack_into(">HB", buf, 16, BGP.MAX_LENGTH + 1, BGP.UPDATE)
  try:
    BGP.ParseBgpHeader(buf, verbose=False)
  except ValueError:
    print "packet too long - ParseBgpHeader raised ValueError"

  # set an incorrect type
  #
  struct.pack_into(">HB", buf, 16, BGP.MIN_LENGTH, 99)
  try:
    BGP.ParseBgpHeader(buf, verbose=False)
  except ValueError:
    print "invalid type - ParseBgpHeader raised ValueError"


def TestBgpRouteRefresh():
  """BGP ROUTE-REFRESH related tests."""

  buf = array.array("B", [0] * 4)

  for afi in range(0, 4):
    for reserved in (0, 1):
      for safi in range(0, 4):
        struct.pack_into(">HBB", buf, 0, afi, reserved, safi)
        try:
          print_msg = BGP.ParseBgpRouteRefresh(buf, len(buf))
          print "ParseRouteRefresh succeeded: %s" % "".join(print_msg),
        except ValueError:
          fmt_string = "ParseRouteRefresh raised ValueError for (%d, %d, %d)"
          print fmt_string % (afi, reserved, safi)


def main():
  TestBgpHeader()
  TestBgpRouteRefresh()


if __name__ == "__main__":
  main()
