from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from pydantic import BaseModel

app = FastAPI()


class User(BaseModel):
    username: str
    password: str


# in production you can use Settings management
class Settings(BaseModel):
    authjwt_secret_key: str = "secret"
    authjwt_token_location: set = {"cookies"}
    authjwt_cookie_csrf_protect: bool = False
    authjwt_denylist_enabled: bool = True
    authjwt_denylist_token_checks: set = { "access", "refresh"}


# callback to get your configuration
@AuthJWT.load_config
def get_config():
    return Settings()


#exception handler for authjwt
# in production , you can tweak performance using or json response
@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={ "detail": exc.message})


# A storage engine to save revoked tokens. in production,
# you can use Redis for storage system
denylist = set()


@AuthJWT.token_in_denylist_loader
def check_if_token_in_denylist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in denylist


# provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token to use authorization
# later in endpoint protected
@app.post('/login')
def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != "string" or user.password != "string":
        raise HTTPException(status_code=401, detail="Bad username or pasword")

    # subject identifier for who this token is for example id or username from database
    access_token = Authorize.create_access_token(subject=user.username, fresh=True)
    refresh_token = Authorize.create_refresh_token(subject=user.username)

    # Set the JWT Cookies in the response
    Authorize.set_access_cookies(access_token)
    Authorize.set_refresh_cookies(refresh_token)
    return { "access_token": access_token, "refresh_token": refresh_token}


# protect endpoint with function jwt_required(), which requires
# a valid access token in the request headers to access.
@app.get('/user')
def user(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_subject()
    return { "user": current_user}


@app.post('/refresh')
def refresh(Authorize: AuthJWT = Depends()):
    """
    The jwt_refresh_token_required() function insures a valid refresh
    token is present in the request before running any code below that function.
    we can use the get_jwt_subject() function to get the subject of the refresh
    token, and use the create_access_token() function again to make a new access token
    """
    Authorize.jwt_refresh_token_required()
    # 헤더에 access_token 을 실어서 요청하면
    # 에러 발생 => {"detail": "Only refresh tokens are allowed" }

    current_user = Authorize.get_jwt_subject()
    new_access_token = Authorize.create_access_token(subject=current_user, fresh=False)
    Authorize.set_access_cookies(new_access_token)
    return { "access_token": new_access_token}


@app.delete('/logout')
def logout(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    Authorize.unset_jwt_cookies()
    return { "msg": "Successfully logout"}


# Endpoint for revoking the current users access token
@app.delete("/access-revoke")
def access_revoke(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    jti = Authorize.get_raw_jwt()['jti']
    denylist.add(jti)
    return { "detail": "Access token has been revoke"}


# Endpoint for revoking the current users refresh token
@app.delete("/refresh-revoke")
def refresh_revoke(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

    jti = Authorize.get_raw_jwt()['jti']
    denylist.add(jti)
    return { "detail": "Refresh token has been revoke"}


@app.post('/fresh-login')
def fresh_login(user: User, Authorize: AuthJWT = Depends()):
    """
    Fresh login endpoint. This is designed to be used if we need to
    make a fresh token for a user (by verifying they have the
    correct username and password). Unlike the standard login endpoint,
    this will only return a new access token, so that we don't keep
    generating new refresh tokens, which entirely defeats their point.
    """
    if user.username != "string" and user.password != "string":
        raise HTTPException(status_code=401, detail="Bad username or password")
    new_access_token = Authorize.create_access_token(subject=user.username, fresh=True)
    return { "access_token": new_access_token}


# Any valid JWT access token can access this endpoint
@app.get("/protected")
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_subject()
    return { "user": current_user}


@app.get('/partially-protected')
def partially_protected(Authorize: AuthJWT = Depends()):
    # In some cases you want to use one endpoint for both,
    #  protected and unprotected. In this situation you can use function jwt_optional().
    Authorize.jwt_optional()
    # If no jwt is sent in the request, get_jwt_subject() will return None
    current_user = Authorize.get_jwt_subject() or "anonymous"
    return { "user": current_user}


# Only fresh JWT access token can access this endpoint
@app.get('/protected-fresh')
def protected_fresh(Authorize: AuthJWT = Depends()):
    Authorize.fresh_jwt_required()

    current_user = Authorize.get_jwt_subject()
    return { "user": current_user}
