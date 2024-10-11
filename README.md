# A simple Flask App with Google OIDC 
An example flask app with google oidc auth 

# How to run this app

Create a google oidc client in google workspace. https://console.cloud.google.com/apis/credentials and Assign the callback url and authorized redirect url accordingly to wherever this app is hosted

Make sure these environment variables are set:
```bash
# .env file
GOOGLE_CLIENT_ID="<from_google_workspace>"
GOOGLE_CLIENT_SECRET="<from_google_workspace>"
SERVER_BASE_URL="https://tuna.in-a-can.ts.net"
```

when all of those are set, you're good to just run the flask application.

# Running the app for local development
You can use either https://ngrok.com/ or tailscale to expose this app to https.
* ngrok: `ngrok http 5000`
* tailscale `sudo tailscale serve 5000`

You should get a HTTPS server base uri, replace `SERVER_BASE_URL` env variable using that.

Afterwards, we can run this on localhost.
```bash
source .env
FLASK_APP=app.py flask.py
```
