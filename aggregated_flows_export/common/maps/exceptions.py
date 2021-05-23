class SavedMapException(Exception):
    """Base exception for errors in saved maps creation or map views"""
    pass


class SavedMapIsEmpty(SavedMapException):
    """Raised when the saved map is empty"""
    pass


class SavedMapCreationFailed(SavedMapException):
    """Raised when saved map creation has failed"""
    pass


class SavedMapNotFound(SavedMapException):
    """Raised when the saved map is not found in Centra"""
    pass


class SavedMapIsNotReady(SavedMapException):
    """Raised when the saved map status should be ready but it is not"""
    pass


class NoFlowsMatchTheFilter(SavedMapException):
    """Raised when the map view is empty because no flows match the required map filter"""
    pass


class MapExportJobError(SavedMapException):
    """Raised the status of the map to flows export job indicates a failure"""
    pass


class MapExportTimedOut(SavedMapException):
    """Raised the export job times out"""
    pass


class GraphGenerationTimedOut(SavedMapException):
    """Raised the export job times out"""
    pass
