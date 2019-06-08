using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ScottBrady91.SignInWithApple.Example.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> TestChallenge()
        {
            var result = await HttpContext.AuthenticateAsync();

            if (result.Succeeded)
            {
                return RedirectToAction("Index");
            }

            return Challenge("apple");
        }

        public async Task<IActionResult> SignOut()
        {
            await HttpContext.SignOutAsync("cookie");
            return RedirectToAction("Index");
        }
    }
}
