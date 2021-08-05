package main

import (
    "encoding/json"
    "ethereum-auth-demo/main/domain"
    "fmt"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/common/hexutil"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/gorilla/mux"
    "github.com/rs/cors"
    "github.com/joho/godotenv"
    "log"
    "net/http"
    "os"
    "strings"
)

type Response struct {
    Message string `json:"message"`
}

func HandleGetAuth() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var message = ""
        var address = ""
        q := r.URL.Query()
        m := q.Get("message")
        a := q.Get("address")
        if m != "" {
            message = m
        } else {
            http.Error(w, "Message is empty.", http.StatusInternalServerError)
            return
        }
        if a != "" {
            address = a
        } else {
            http.Error(w, "Address is empty.", http.StatusInternalServerError)
            return
        }

        vars := mux.Vars(r)
        signature := vars["signature"]
        fromAddr := common.HexToAddress(strings.ToLower(address))

        hash := signHash([]byte(message))
        sig := hexutil.MustDecode(signature)

        if sig[64] != 27 && sig[64] != 28 {
            http.Error(w, "failed.", http.StatusInternalServerError)
            return
        }
        sig[64] -= 27

        pubKey, err := crypto.SigToPub(hash, sig)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        recoveredAddr := crypto.PubkeyToAddress(*pubKey)

        log.Print("fromAddr: " + fromAddr.Hex())
        log.Print("recoveredAddr: " + recoveredAddr.Hex())
        log.Print(fromAddr.Hex() == recoveredAddr.Hex())

        jwtToken, err := domain.GetJWT(fromAddr.Hex())
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        log.Print(jwtToken)

        response := Response{"Authorized: " + jwtToken}

        jsonResponse, err := json.Marshal(response)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        w.Write(jsonResponse)
    }
}

/**
 * A message used on ethers.js must have prefix.
 *
 * See https://gist.github.com/dcb9/385631846097e1f59e3cba3b1d42f3ed#file-eth_sign_verify-go
 */
func signHash(data []byte) []byte {
    msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
    return crypto.Keccak256([]byte(msg))
}

func main() {
    r := mux.NewRouter()

    err := godotenv.Load("config/.env")
    if err != nil {
        log.Print(err.Error())
        log.Print("Error loading .env")
    }

    getPath := func(path string) string {
        return "/v1" + path
    }

    r.Handle(getPath("/auth/{signature}"), HandleGetAuth()).Methods("GET")

    port := os.Getenv("PORT")
    if port == "" {
        port = "9000"
    }

    c := cors.New(cors.Options{
        AllowedOrigins: []string{
            "http://localhost:3000",
        },
        AllowCredentials: true,
        AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
    })

    server := &http.Server{
        Addr:    ":" + port,
        Handler: c.Handler(r),
    }
    if err := server.ListenAndServe(); err != nil {
        log.Print(err)
    }
}
