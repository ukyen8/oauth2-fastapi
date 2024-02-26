import logging
import os

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from google.auth.external_account_authorized_user import Credentials
from google_auth_oauthlib import flow
from googleapiclient.discovery import build

app = FastAPI()
logger = logging.getLogger("uvicorn")

if not os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


@app.get("/authorize")
async def authorize_google_oauth2() -> Response:
    auth_flow = flow.Flow.from_client_secrets_file(
        client_secrets_file="client_secret.json",
        scopes=_get_scopes(),
    )
    auth_flow.redirect_uri = "http://localhost:8080/oauth2callback"

    authorization_url, _ = auth_flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
    )

    return RedirectResponse(url=authorization_url)


@app.get("/oauth2callback")
async def oauth2callback_google_oauth2(
    request: Request,
    state: str | None = None,
) -> Response:
    auth_flow = flow.Flow.from_client_secrets_file(
        client_secrets_file="client_secret.json",
        scopes=_get_scopes(),
        state=state,
    )
    auth_flow.redirect_uri = "http://localhost:8080/oauth2callback"

    authorization_response = str(request.url)
    logger.info(f"{authorization_response=}")
    auth_flow.fetch_token(authorization_response=authorization_response)

    credentials = auth_flow.credentials
    with open("oauth_credentials.json", "w") as fout:
        fout.write(credentials.to_json())

    return RedirectResponse(url="https://www.google.com")


@app.get("/userinfo")
async def get_user_info() -> Response:
    credentials = Credentials.from_file("oauth_credentials.json")
    client = build("oauth2", "v2", credentials=credentials)
    response = client.userinfo().get().execute()
    return JSONResponse(content={"email": response["email"], "name": response["name"]})


def _get_scopes() -> list[str]:
    return [
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
    ]
