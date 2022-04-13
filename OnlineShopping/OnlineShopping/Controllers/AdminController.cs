using OnlineShopping.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;


namespace OnlineShopping.Controllers
{
    public class AdminController : Controller
    {
        #region Admin Login ...
        [AllowAnonymous]
        public ActionResult Index(string returnUrl)
        {
            LoginViewModel loginModel = new LoginViewModel();
            loginModel.UserEmailId = Request.Cookies["RememberMe_UserEmailId"] != null ? Request.Cookies["RememberMe_UserEmailId"].Value : "";
            loginModel.Password = Request.Cookies["RememberMe_Password"] != null ? Request.Cookies["RememberMe_Password"].Value : "";

            ViewBag.ReturnUrl = returnUrl;
            return View(loginModel);
        }
        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ValidateInput(false)]
        public ActionResult Index(LoginViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                string EncryptedPassword = EncryptDecrypt.Encrypt(model.Password, true);
                var user = _unitOfWork.GetRepositoryInstance<Tbl_Members>().GetFirstOrDefaultByParameter(i => i.EmailId == model.UserEmailId && i.Password == EncryptedPassword && i.IsActive == true && i.IsDelete == false);

                if (user != null)
                {
                    Session["MemberId"] = user.MemberId;
                    var roles = _unitOfWork.GetRepositoryInstance<Tbl_MemberRole>().GetFirstOrDefaultByParameter(i => i.MemberId == user.MemberId && i.RoleId == model.UserType);

                    if (roles != null)
                    {
                        Response.Cookies["MemberRole"].Value = _unitOfWork.GetRepositoryInstance<Tbl_Roles>().GetFirstOrDefaultByParameter(i => i.RoleId == model.UserType).RoleName;
                    }
                    else
                    {
                        ModelState.AddModelError("Password", "Password is wrong");
                        return View(model);
                    }
                }
                else
                {
                    ModelState.AddModelError("Password", "Invalid email address or password");
                }
            }
            return View(model);
        }
        #endregion
    }
}