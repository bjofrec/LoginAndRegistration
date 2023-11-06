#pragma warning disable CS8618
using System.ComponentModel.DataAnnotations;
namespace LoginAndRegistration.Models;
public class UserLogin
{
    [Required]    
    [EmailAddress]
    public string Email { get; set; }    
    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; } 
}