using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using LoginAndRegistration.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Filters;

namespace LoginAndRegistration.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private MyContext _context;

    public HomeController(ILogger<HomeController> logger, MyContext context)
    {
        _logger = logger;

        _context = context;
    }

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }
    [HttpPost("user/create")]
    public IActionResult CreateUser(User user){
        if (ModelState.IsValid){
            PasswordHasher<User> Hasher = new PasswordHasher<User>();   
            user.Password = Hasher.HashPassword(user, user.Password); 
            _context.Add(user);
            _context.SaveChanges();
            return RedirectToAction("Index");
        }else{
            return RedirectToAction("Index");
        }
    }

    [HttpPost("/login")]
    public IActionResult Login(UserLogin userSubmission) 
    {

        if (!ModelState.IsValid) 
        {
            return View("Index"); 
        }
        
        User? user = _context.Users.FirstOrDefault(e => e.Email == userSubmission.Email);


        if (user == null)
        {
            ModelState.AddModelError("Email", "Invalid Email Address/Password");
            return View("Index");
        }
        PasswordHasher<UserLogin> hashbrowns = new PasswordHasher<UserLogin>();
        var result = hashbrowns.VerifyHashedPassword(userSubmission, user.Password, userSubmission.Password);
        if (result == 0)
        {
            ModelState.AddModelError("Email", "Invalid Email Address/Password");
        }
        HttpContext.Session.SetInt32("UUID", user.UserId);
        return View("Principal");

    }

    [HttpGet("/principal")]
    public IActionResult Principal()
    {

        return View();
    }

    public IActionResult Logout(){

        HttpContext.Session.Clear();
        return RedirectToAction("Index");
    }



    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
