class DjangoDiscordAuthError(Exception):
    pass


class TokenError(DjangoDiscordAuthError):
    pass


class TokenExpiredError(TokenError):
    pass


class TokenInvalidError(TokenError):
    pass


class TokenNotRefreshableError(TokenError):
    pass


class IncompleteResponseError(DjangoDiscordAuthError):
    pass
