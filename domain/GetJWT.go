package domain

import (
    jwt "github.com/form3tech-oss/jwt-go"
    "os"
    "time"
)

func GetJWT(address string) (string, error) {
    token := jwt.New(jwt.SigningMethodHS256)

    claims := token.Claims.(jwt.MapClaims)
    claims["admin"] = true
    claims["sub"] = address
    claims["name"] = "name_" + address
    claims["iat"] = time.Now().Unix()
    //claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
    claims["exp"] = time.Now().Add(time.Minute * 3).Unix()

    tokenString, err := token.SignedString([]byte(os.Getenv("TOKEN_SIGNING_KEY")))
    if err != nil {
        return "", err
    }

    return tokenString, nil
}
