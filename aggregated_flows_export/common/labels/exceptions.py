class LabelException(Exception):
    """ Parent class for exceptions related to label operations """
    pass


class LabelNotFoundInCentra(LabelException):
    """ Raised when a label with the supplied key, value is not found in Centra """
    pass


class IllegalLabelException(LabelException):
    """Raised when a string is not a legal label """
    pass


class LabelContainsIllegalCharacters(IllegalLabelException):
    """ Raised when the label's key or value contains illegal characters """
    pass


class LabelKeyOrValueIsEmpty(IllegalLabelException):
    """ Raised when the label's key or value evaluate is empty ("", None) """
    pass
