package cliente

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

func registrarse() {
	url := "https://example.com/register"

	// Datos del usuario y contraseña a registrar
	user := "johndoe"
	password := "mypassword"

	// Codificamos la contraseña en base64 para enviarla como texto plano
	encodedPassword := base64.StdEncoding.EncodeToString([]byte(password))

	// Creamos un cuerpo de solicitud para enviar los datos del usuario y contraseña
	body := bytes.NewBufferString(fmt.Sprintf("user=%s&pass=%s", user, encodedPassword))

	// Enviamos una solicitud POST a la dirección /register con el cuerpo de la solicitud
	resp, err := http.Post(url, "application/x-www-form-urlencoded", body)
	if err != nil {
		// Error al enviar la solicitud
		fmt.Println("Error al enviar la solicitud:", err)
		return
	}

	// Leemos la respuesta del servidor
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	responseBody := buf.String()

	fmt.Println(responseBody)
}

func Run() {

	var opcion int
	for {
		fmt.Println("Elija una opción:")
		fmt.Println("1. Registrarse")
		fmt.Println("2. Salir")

		fmt.Scanln(&opcion)

		switch opcion {
		case 1:
			registrarse()
		case 2:
			os.Exit(0)
		default:
			fmt.Println("Opción no válida")
		}
	}

}
