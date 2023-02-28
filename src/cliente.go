package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

// Define una estructura para las credenciales de usuario
type Credential struct {
    ID       int    `json:"id"`
    UserID   int    `json:"user_id"`
    Username string `json:"username"`
    Password string `json:"password"`
}

// Define una estructura para los tokens de acceso
type Token struct {
    AccessToken string `json:"access_token"`
}

// Define una estructura para las respuestas de error
type ErrorResponse struct {
    Message string `json:"message"`
}

func main() {
    // Define la dirección IP y el puerto del servidor
    serverAddr := "http://localhost:8080"

    // Crea una nueva solicitud HTTP para iniciar sesión
    loginData := Credential{
        Username: "admin",
        Password: "password",
    }
    loginJSON, _ := json.Marshal(loginData)
    loginReq, _ := http.NewRequest("POST", fmt.Sprintf("%s/login", serverAddr), bytes.NewBuffer(loginJSON))
    loginReq.Header.Set("Content-Type", "application/json")

    // Realiza la solicitud de inicio de sesión al servidor
    loginResp, err := http.DefaultClient.Do(loginReq)
    if err != nil {
        fmt.Println("Error al realizar la solicitud de inicio de sesión:", err)
        return
    }
    defer loginResp.Body.Close()

    // Lee el token de acceso desde la respuesta del servidor
    var token Token
    if err := json.NewDecoder(loginResp.Body).Decode(&token); err != nil {
        fmt.Println("Error al leer el token de acceso:", err)
        return
    }

    // Crea una nueva solicitud HTTP para obtener todas las credenciales
    listReq, _ := http.NewRequest("GET", fmt.Sprintf("%s/credentials", serverAddr), nil)
    listReq.Header.Set("Content-Type", "application/json")
    listReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

    // Realiza la solicitud de listar las credenciales al servidor
    listResp, err := http.DefaultClient.Do(listReq)
    if err != nil {
        fmt.Println("Error al realizar la solicitud de listar las credenciales:", err)
        return
    }
    defer listResp.Body.Close()

    // Lee la lista de credenciales desde la respuesta del servidor
    var credentials []Credential
    if err := json.NewDecoder(listResp.Body).Decode(&credentials); err != nil {
        fmt.Println("Error al leer las credenciales:", err)
        return
    }

    // Imprime la lista de credenciales en la consola
    fmt.Println(credentials)
}
