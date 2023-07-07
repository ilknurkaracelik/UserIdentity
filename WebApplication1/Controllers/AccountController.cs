using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using WebApplication1.Identity;
using WebApplication1.Models;

namespace WebApplication1.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private UserManager<ApplicationUser> userManager;
        // GET: Account
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }
        [AllowAnonymous]
        public ActionResult Index()
        {
            return View();
        }
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                return View("Error", new string[] { "Erişim Hakkınız Yok" });
            }
            ViewBag.returnUrl = returnUrl;
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public ActionResult Login(LoginModel model,string returnUrl)
        {
            if (ModelState.IsValid)
            {
                var user = userManager.Find(model.UserName, model.Password);

                if (user == null)
                {
                    ModelState.AddModelError("", "Yanlış kullanıcı adı veya parola");
                }
                else
                {
                    var authManager = HttpContext.GetOwinContext().Authentication;

                    var identity = userManager.CreateIdentity(user, "ApplicationCookie");

                    var authProperties = new AuthenticationProperties()
                    {
                        IsPersistent = true

                    };

                    authManager.SignOut();
                    authManager.SignIn(authProperties, identity);

                    return Redirect(string.IsNullOrEmpty( returnUrl) ? "/":returnUrl);
                }
            }

            ViewBag.returnUrl = returnUrl;
            return View(model);
        }
        public AccountController()
        {
            userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new IdentityDataContext()));

            userManager.PasswordValidator = new CustomPasswordValidator()
            { 
             RequireDigit=true,
             RequiredLength=7,
             RequireLowercase=true,
             RequireNonLetterOrDigit=true,
             RequireUppercase=true
            };

            userManager.UserValidator = new UserValidator<ApplicationUser>(userManager)
            {
                RequireUniqueEmail = true,
                AllowOnlyAlphanumericUserNames = false
            };
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public ActionResult Register(Register model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser();
                user.UserName = model.UserName;
                user.Email = model.Email;

                var result = userManager.Create(user, model.Password);

                if (result.Succeeded)
                {
                    userManager.AddToRole(user.Id, "User");
                    return RedirectToAction("Login");
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }
            }


            return View(model);
        }

        public ActionResult Logout()
        {
            var authManager = HttpContext.GetOwinContext().Authentication;
            authManager.SignOut();

            return RedirectToAction("Login");
        }
    }
}