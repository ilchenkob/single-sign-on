using MapleWebsite.Models;
using MapleWebsite.SingleSignOn.Services;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Diagnostics;

namespace MapleWebsite.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult LoginWithSso()
        {
            var companyId = Guid.NewGuid(); // Get company ID from DB by user email domain

            var loginRequest = SingleSignOnService.GetLoginRequest(companyId);

            ViewData["LoginUrl"] = loginRequest.loginUrl;
            ViewData["SAMLRequest"] = loginRequest.samlRequest;

            return View();
        }

        [HttpPost]
        public IActionResult LogoutWithSso()
        {
            var companyId = Guid.NewGuid();
            var logoutRequest = SingleSignOnService.GetLogoutUrl(companyId);

            ViewData["LogoutUrl"] = logoutRequest.logoutUrl;
            ViewData["SAMLRequest"] = logoutRequest.samlRequest;

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}