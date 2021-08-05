package domain

import (
    jwt "github.com/form3tech-oss/jwt-go"
    "time"
)

func GetJWT(address string) (string, error) {
    token := jwt.New(jwt.SigningMethodHS256)

    claims := token.Claims.(jwt.MapClaims)
    claims["admin"] = true
    claims["sub"] = address
    claims["name"] = "name_" + address
    claims["iat"] = time.Now().Unix()
    claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

    tokenString, err := token.SignedString([]byte("Aa*fp*HTZiz&^n@Z&BY%mM:G"))
    if err != nil {
        return "", err
    }

    return tokenString, nil
}
