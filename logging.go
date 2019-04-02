package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gobuffalo/envy"
)

type action struct {
	Title  string
	Verb   string
	Status string
}

//ActionList is a map of all possible action in logs
var ActionList = map[string]action{
	"create": action{"New ", " has been created.", "success"},
	"edit":   action{"Edit ", " has been edited.", "success"},
	"delete": action{"Delete ", " has been deleted.", "alert"},
	"login":  action{"Login ", " logged in.", "info"},
}

func getUsernameFromToken(tokenString string) (string, error) {
	//Parse token to remove the bearer
	if strings.Contains(tokenString, "Bearer ") {
		tokenString = strings.Split(tokenString, "Bearer ")[1]
	}

	key, err := envy.MustGet("JWT_SECRET")

	// Parse takes the token string and a function for looking up the key.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", errors.New("Could not parse claims or invalid token")
	}

	return claims["username"].(string), nil
}

//PostNewLog to the logging API, object is the model name to be used and name the object name itself (like a device name)
func PostNewLog(token string, a action, object string, name string) error {
	//url := "http://localhost:3002/api/v1/logs"
	url, erro := envy.MustGet("LOGGING_API")
	if erro != nil {
		return erro
	}

	var logTitle = a.Title + strings.ToLower(object)
	var logContent = object + " " + name + a.Verb
	var logCreator, err = getUsernameFromToken(token)
	if err != nil {
		//logCreator = "Unknown"
		return err
	}

	values := map[string]string{"title": logTitle, "content": logContent, "creator": logCreator, "status": a.Status}
	jsonStr, _ := json.Marshal(values)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		return errors.New("Logging API responded with a non 2xx status")
	}

	// fmt.Println("response Status:", resp.Status)
	// body, _ := ioutil.ReadAll(resp.Body)

	return nil
}
