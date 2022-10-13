__code_version__ = 'v1.0.0'

class UsageError(Exception):
    """ Define a custom exception to trigger the argparse print_help method """

    def __init__(self, msg="An unknown error occurred"):
        Exception.__init__(self, msg)
        self.message = msg

class ValidationFailedError(Exception):
    """ Used when objects fail their validation checks """

    def __init__(self, msg="Failed self.validate()"):
        Exception.__init__(self, msg)
        self.message = msg
