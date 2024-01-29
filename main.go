package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	googleOauthConfig *oauth2.Config
	oauthStateString   = "AnjayyyyyState"
	store             = sessions.NewCookieStore([]byte("justLearnNothingToSeeHere"))
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/callback",
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
}

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/logout", handleLogout)
	http.ListenAndServe(":8080", nil)
}


func handleHome(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	var html string

	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		email, _ := session.Values["email"].(string)
		picture, _ := session.Values["picture"].(string)

		html = fmt.Sprintf(`
	<!DOCTYPE html>
	<html lang="en">
	<head>
	    <meta charset="UTF-8">
	    <meta name="viewport" content="width=device-width, initial-scale=1.0">
	    <title>Google Login</title>
	    <style>
	        body {
	            display: flex;
	            justify-content: center;
	            align-items: center;
	            height: 100vh;
	            margin: 0;
	        }

			.logout-button {
	            background-color: #FF0000;
	            color: #fff;
	            padding: 10px 20px;
	            font-size: 16px;
	            border: none;
	            border-radius: 4px;
	            cursor: pointer;
	            margin-top: 20px;
	        }
	    </style>
	</head>
	<body>
	    <h1>Welcome!</h1>
	    <p>Email: %s</p>
	    <img src="%s" alt="Profile Picture" width="100">

		<button class="logout-button" onclick="redirectToLogout()">Logout</button>

		<script>
		function redirectToLogout() {
			window.location.href = "/logout";
		}
	</script>
	</body>
	</html>
	`, email, picture)
		
	} else {
		html = `
		<!DOCTYPE html>
		<html lang="en">
		<head>
		    <meta charset="UTF-8">
		    <meta name="viewport" content="width=device-width, initial-scale=1.0">
		    <title>Google Login</title>
		    <style>
		        body {
		            display: flex;
		            justify-content: center;
		            align-items: center;
		            height: 100vh;
		            margin: 0;
		        }

		        .google-login-button {
		            background-color: #4285F4;
		            color: #fff;
		            padding: 10px 20px;
		            font-size: 16px;
		            border: none;
		            border-radius: 4px;
		            cursor: pointer;
		        }
		    </style>
		</head>
		<body>
		    <button class="google-login-button" onclick="redirectToLogin()">Google Login</button>

		    <script>
		        function redirectToLogin() {
		            window.location.href = "/login";
		        }
		    </script>
		</body>
		</html>
		`
	}

	fmt.Fprint(w, html)
}


func handleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	content, err := getUserInfo(r.FormValue("state"), r.FormValue("code"))
	if err != nil {
		fmt.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var userInfo map[string]interface{}
	err = json.Unmarshal(content, &userInfo)
	if err != nil {
		fmt.Println("Error parsing user info:", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = true
	session.Values["email"] = userInfo["email"].(string)
	session.Values["picture"] = userInfo["picture"].(string)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	session.Values["authenticated"] = false
	session.Values["email"] = ""
	session.Values["picture"] = ""
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func getUserInfo(state string, code string) ([]byte, error) {
	if state != oauthStateString {
		return nil, fmt.Errorf("invalid oauth state")
	}

	token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %s", err.Error())
	}

	return contents, nil
}
