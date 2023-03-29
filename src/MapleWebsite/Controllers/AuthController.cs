using MapleWebsite.Models;
using MapleWebsite.SingleSignOn.Services;
using Microsoft.AspNetCore.Mvc;

namespace MapleWebsite.Controllers
{
    public class AuthController : Controller
    {
        [HttpPost]
        public IActionResult Login([FromForm] SamlResponse response)
        {
            var result = SingleSignOnService.ValidateSamlResponse(response?.SAMLResponse);

            ViewData["success"] = result.isSuccess;
            ViewData["email"] = result.userEmail;

            return View();
        }
    }
}