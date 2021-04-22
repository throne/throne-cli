#    Copyright (C) 2021  Dakota Gartley
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

class ThroneBaseException(Exception):
    """
    All exceptions encompass this exception
    """

class ThroneParsingError(ThroneBaseException):
    """
    An exception for when a parser fails to parse the
    received data correctly
    """

class ThroneFormattingError(ThroneBaseException):
    """
    An exception for when results/returns are not
    formatted correctly
    """

class ThroneLookupFailed(ThroneBaseException):
    """
    An exception for when whatever was looked up
    failed
    """

class ThroneHTTPError(ThroneBaseException):
    """
    An exception for various HTTP errors encountered.
    """