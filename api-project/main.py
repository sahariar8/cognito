from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from dotenv import load_dotenv
from pydantic.alias_generators import to_camel


import boto3
import base64
import hmac
import hashlib
import uvicorn
import os



app = FastAPI()

# Cognito details
load_dotenv() 
CLIENT_ID = os.getenv('CLIENT_ID')
print(CLIENT_ID,'client')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')  # Replace with your client secret
REGION =os.getenv('REGION')
JWT_SECRET =os.getenv('JWT_SECRET')

cognito_client = boto3.client('cognito-idp', region_name=REGION)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
    username: str
    password: str
    email: str

class UserRegistrationConfirmSchema(BaseModel):
    username: str
    confirmation_code: str

class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str
    class Config:
        alias_generator = to_camel
        populate_by_name = True



# Function to calculate SECRET_HASH for Cognito
def get_secret_hash(username: str, client_id: str, client_secret: str) -> str:
    message = username + client_id
    dig = hmac.new(client_secret.encode('utf-8'),
                   message.encode('utf-8'), hashlib.sha256).digest()
    secret_hash = base64.b64encode(dig).decode()
    return secret_hash

# Signup route
@app.post("/signup", response_model=dict)
def signup(user: User):
    try:
        response = cognito_client.sign_up(
            ClientId=CLIENT_ID,
            Username=user.username,
            Password=user.password,
            SecretHash= get_secret_hash(user.username, CLIENT_ID, CLIENT_SECRET),
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': user.email
                },
            ]
        )
        return response
    except cognito_client.exceptions.UsernameExistsException:
        raise HTTPException(status_code=400, detail='Username already exists')
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Confirm signup route
@app.post("/confirm", response_model=dict)
def confirm(user: UserRegistrationConfirmSchema):
    try:
        response = cognito_client.confirm_sign_up(
            ClientId=CLIENT_ID,
            Username=user.username,
            ConfirmationCode=user.confirmation_code,
            SecretHash=get_secret_hash(user.username, CLIENT_ID, CLIENT_SECRET)
        )
        return response
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Signin route
@app.post("/signin", response_model=Token)
def signin(user: User):
    try:
        response = cognito_client.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': user.username,
                'PASSWORD': user.password,
                'SECRET_HASH': get_secret_hash(user.username, CLIENT_ID, CLIENT_SECRET)
            },
            ClientId=CLIENT_ID
        )
        
        auth_res = response['AuthenticationResult']
        
        access_token = auth_res['AccessToken']
        token_type = auth_res['TokenType']
        refresh_token = auth_res['RefreshToken']
        
        return {"accessToken": access_token, "tokenType": token_type, "refreshToken": refresh_token}
    except cognito_client.exceptions.NotAuthorizedException:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    
@app.get("/user")
def get_user(token: str = Depends(oauth2_scheme)):
    try:
        # Fetch user information from Cognito using the Access Token
        user_info = cognito_client.get_user(
            AccessToken=token
        )
        
        return {
            "email": user_info['UserAttributes'][0]["Value"],
            "sub": user_info['UserAttributes'][2]["Value"]
        }  # Returns the user attributes, e.g., email, phone
    except cognito_client.exceptions.NotAuthorizedException:
        raise HTTPException(status_code=401, detail="Invalid or expired access token.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")



@app.post("/logout", response_model=dict)
def logout(token: str = Depends(oauth2_scheme)):
   
    try:
        # Call AWS Cognito's global sign-out to invalidate the session
        response = cognito_client.global_sign_out(
            AccessToken=token,
            
        )
        return {"message": "Successfully logged out"}
    
    except cognito_client.exceptions.NotAuthorizedException:
        raise HTTPException(status_code=401, detail="Invalid or expired access token.")
    except cognito_client.exceptions.InvalidParameterException:
        raise HTTPException(status_code=400, detail="Invalid token parameters.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=3000, reload=True)
