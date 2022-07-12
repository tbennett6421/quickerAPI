from src.classes.BuildingBlocks import State

class SharedEngine(State):
    """
        The SharedEngine will be the Singleton class used as a dependency
        from which external things may be called. This should be created
        or populated by the main app, then injected as a dependency to
        routes

        The layout of the engine shall strive to look like the following
            se: the root key

                app: an application that can be called
                    alexa:  an alexa top1m lookup service
                    cisco:  a cisco umbrella lookup service

        Examples
            app.se.alexa
            app.se.cisco
            se.alexa
            se.cisco
    """

    def __init__(self):
        super().__init__()
