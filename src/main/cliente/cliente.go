package cliente

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"main/util"
	"net/http"
	"net/url"
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

// chk comprueba y sale si hay errores (ahorra escritura en programas sencillos)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func registrarse() {
	// Pedimos al usuario que ingrese su nombre de usuario y contraseña
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Ingresa tu nombre de usuario: ")
	scanner.Scan()
	user := scanner.Text()
	fmt.Print("Ingresa tu contraseña: ")
	scanner.Scan()
	pass := scanner.Text()

	// creamos un cliente especial que no comprueba la validez de los certificados
	// esto es necesario por que usamos certificados autofirmados (para pruebas)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(pass))
	keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
	keyData := keyClient[32:64] // la otra para los datos (256 bits)

	// generamos un par de claves (privada, pública) para el servidor
	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Printf("Error al generar las claves: %v", err)
	}
	pkClient.Precompute() // aceleramos su uso con un precálculo

	pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
	if err != nil {
		fmt.Printf("Error al codificar la clave privada: %v", err)
	}

	keyPub := pkClient.Public()           // extraemos la clave pública por separado
	pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
	if err != nil {
		fmt.Printf("Error al codificar la clave pública: %v", err)
	}

	// ** ejemplo de registro
	data := url.Values{} // estructura para contener los valores
	data.Set("cmd", "register")
	data.Set("user", user)
	data.Set("pass", util.Encode64(keyLogin)) // "contraseña" a base64

	// comprimimos y codificamos la clave pública
	data.Set("pubkey", util.Encode64(util.Compress(pubJSON)))

	// comprimimos, ciframos y codificamos la clave privada
	data.Set("prikey", util.Encode64(util.Encrypt(util.Compress(pkJSON), keyData)))

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	if err != nil {
		fmt.Printf("Error al enviar la solicitud al servidor: %v", err)
	}
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	r.Body.Close()             // hay que cerrar el reader del body
	fmt.Println()
}

func login() {
	// Pedimos al usuario que ingrese su nombre de usuario y contraseña
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Ingresa tu nombre de usuario: ")
	scanner.Scan()
	user := scanner.Text()
	fmt.Print("Ingresa tu contraseña: ")
	scanner.Scan()
	pass := scanner.Text()

	// creamos un cliente especial que no comprueba la validez de los certificados
	// esto es necesario por que usamos certificados autofirmados (para pruebas)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(pass))
	keyLogin := keyClient[:32] // una mitad para el login (256 bits)

	// generamos un par de claves (privada, pública) para el servidor
	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Printf("Error al generar las claves: %v", err)
	}
	pkClient.Precompute() // aceleramos su uso con un precálculo

	// ** ejemplo de registro
	data := url.Values{} // estructura para contener los valores
	data.Set("cmd", "login")
	data.Set("user", user)
	data.Set("pass", util.Encode64(keyLogin))                  // "contraseña" a base64
	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	if err != nil {
		fmt.Printf("Error al enviar la solicitud al servidor: %v", err)
	}
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	r.Body.Close()             // hay que cerrar el reader del body
	fmt.Println()
}

func Run() {

	var opcion int
	for {
		fmt.Println("Elija una opción:")
		fmt.Println("1. Registrarse")
		fmt.Println("2. Login")
		fmt.Println("3. Salir")

		fmt.Scanln(&opcion)

		switch opcion {
		case 1:
			registrarse()
		case 2:
			login()
		case 3:
			os.Exit(0)
		default:
			fmt.Println("Opción no válida")
		}
	}

}
