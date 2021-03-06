#!/usr/bin/python2.5  # pylint: disable-msg=C6301
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

"""Indent - provide a common routine for indenting structured text."""

__author__ = 'sstuart@google.com (Stephen Stuart)'
__version__ = '1.0'

BMP_HEADER_INDENT = 0
BMP_CONTENT_INDENT = 1
BGP_HEADER_INDENT = 1
BGP_CONTENT_INDENT = 2
BGP_MPATTR_INDENT = 3
INDENT_CHAR = ' '
INDENT_COUNT = 2


def IndentLevel(level):
  """Return a string of spaces at the requested indentation level.

  Args:
    level: int indicating indentation level (0 == no leading spaces)

  Returns:
    A string of spaces.
  """

  return INDENT_CHAR * INDENT_COUNT * level
