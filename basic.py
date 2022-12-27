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


# callback to get your configuration
@AuthJWT.load_config
def get_config():
    return Settings()


#exception handler for authjwt
# in production , you can tweak performance using or json response
@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={ "detail": exc.message})


# provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token to use authorization
# later in endpoint protected
@app.post('/login')
def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or pasword")

    # subject identifier for who this token is for example id or username from database
    access_token = Authorize.create_access_token(subject=user.username)
    refresh_token = Authorize.create_refresh_token(subject=user.username)
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
    new_access_token = Authorize.create_access_token(subject=current_user)
    return { "access_token": new_access_token}


@app.get('/partially-protected')
def partially_protected(Authorize: AuthJWT = Depends()):
    # In some cases you want to use one endpoint for both,
    #  protected and unprotected. In this situation you can use function jwt_optional().
    Authorize.jwt_optional()
    # If no jwt is sent in the request, get_jwt_subject() will return None
    current_user = Authorize.get_jwt_subject() or "anonymous"
    return { "user": current_user}
