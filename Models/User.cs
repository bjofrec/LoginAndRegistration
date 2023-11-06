using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
#pragma warning disable CS8618
namespace LoginAndRegistration.Models;

public class User{
    [Key]
    public int UserId {get; set;}
    [Required]
    [MinLength(2)]
    public string FirstName {get; set;}
    [Required]
    [MinLength(2)]
    public string LastName {get; set;}
    [Required]
    [EmailAddress]
    [UniqueEmail]
    public string Email {get; set;}

    [Required]
    [MinLength(8)]
    [DataType(DataType.Password)]

    public string Password {get; set;}
    [Required]
    [NotMapped]
    [Compare("Password")]
    [DataType(DataType.Password)]
    public string CPassword { get; set; }

    public DateTime Fecha_Creacion {get; set;} = DateTime.Now;
    public DateTime Fecha_Actualizacion {get; set;} = DateTime.Now;

    public class UniqueEmailAttribute : ValidationAttribute
{
    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if(value == null)
        {
            return new ValidationResult("Email is required!");
        }
        MyContext _context = (MyContext)validationContext.GetService(typeof(MyContext));
    	if(_context.Users.Any(e => e.Email == value.ToString()))
        {
            return new ValidationResult("Email must be unique!");
        } else {
            return ValidationResult.Success;
        }
    }
}


}



