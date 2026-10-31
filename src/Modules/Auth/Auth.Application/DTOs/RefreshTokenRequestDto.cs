using System.ComponentModel.DataAnnotations;

namespace Auth.Application.DTOs;

public class RefreshTokenRequestDto
{
    [Required(ErrorMessage = "Refresh token is required")]
    public string RefreshToken { get; set; } = default!;
}
