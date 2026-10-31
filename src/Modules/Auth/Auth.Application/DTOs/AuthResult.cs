namespace Auth.Application.DTOs;

public enum AuthError
{
    None,
    InvalidCredentials,
    LockedOut,
    InactiveUser,
    InvalidRefreshToken
}

public sealed class AuthResult
{
    private AuthResult(LoginResponseDto? data, AuthError error)
    {
        Data = data;
        Error = error;
    }

    public LoginResponseDto? Data { get; }
    public AuthError Error { get; }
    public bool Succeeded => Error == AuthError.None;

    public static AuthResult Success(LoginResponseDto data) => new(data, AuthError.None);
    public static AuthResult Failure(AuthError error) => new(null, error);
}
