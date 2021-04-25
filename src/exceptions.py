# LICENSED UNDER BSD-3-CLAUSE-CLEAR LICENSE
# SEE PROVIDED LICENSE FILE IN ROOT DIRECTORY

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

class ThroneConfigError(ThroneBaseException):
    """
    An exception for when there is an error/issue 
    with the .throne/config.yml file.
    """