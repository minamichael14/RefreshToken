using Microsoft.AspNetCore.Mvc;
using RefreshToken.Helpers;
using RefreshToken.Model;

namespace RefreshToken.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        [HttpPost]
        public ActionResult<AuthenticatedResponse> Login(LoginModel loginModel)
        {
            if (loginModel.Username == "mina" && loginModel.Password == "123")
            {
                var token =  Token.GenerateToken(1, loginModel.Username, "Admin");
                var refreshToken = Token.GenerateRefreshToken();

                Token.SaveRefreshToken(loginModel.Username, refreshToken);


                var respone = new AuthenticatedResponse
                {
                    Token = token,
                    RefreshToken = refreshToken
                };
                return Ok(respone);
            }
            return Unauthorized();

        }

        [HttpPost("refresh")]
        public ActionResult<AuthenticatedResponse> Refresh(RefreshRequest request)
        {
            var principal = Token.GetPrincipalFromExpiredToken(request.Token);
            var username = principal.Identity.Name;

            if (!Token.ValidateRefreshToken(username, request.RefreshToken))
            {
                return Unauthorized("Invalid refresh token");
            }

            var newJwtToken = Token.GenerateToken(1, username, "Admin");
            var newRefreshToken = Token.GenerateRefreshToken();

            Token.SaveRefreshToken(username, newRefreshToken);

            return Ok(new AuthenticatedResponse
            {
                Token = newJwtToken,
                RefreshToken = newRefreshToken
            });
        }
    }
}
