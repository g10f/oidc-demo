class ProtocolError(Exception):
    """
    An error in the exchange with the identity provider, shown to the user on the error page.

    error is the OAuth 2.0 error code (e.g. "access_denied") or one of this demo (e.g. "invalid_id_token"),
    description says in a sentence what went wrong.
    """

    def __init__(self, error, description=''):
        self.error = error
        self.description = description or error
        super().__init__(f'{error}: {self.description}')
