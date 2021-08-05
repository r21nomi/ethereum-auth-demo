package domain

import (
    "fmt"
    jwt "github.com/form3tech-oss/jwt-go"
    "os"
)

type Token struct {
    jwt.StandardClaims
}

func VerifyToken(tokenString string) (*Token, error) {
    token, err := getToken(tokenString)
    if err != nil {
        return nil, err
    }

    if _, ok := token.Claims.(jwt.MapClaims); !ok && !token.Valid {
        return nil, err
    }

    t := Token{}
    _, err = jwt.ParseWithClaims(tokenString, &t, func(token *jwt.Token) (interface{}, error) {
        return []byte(os.Getenv("TOKEN_SIGNING_KEY")), nil
    })
    if err != nil {
        return nil, err
    }

    return &t, nil
}

func getToken(tokenString string) (*jwt.Token, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(os.Getenv("TOKEN_SIGNING_KEY")), nil
    })
    if err != nil {
        return nil, err
    }
    return token, nil
}
