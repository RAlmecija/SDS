/*
Este programa demuestra una arquitectura cliente servidor sencilla utilizando HTTPS. También demuestra los siguientes conceptos:
- Organización del código en paquetes
- Esquema básico de autentificación (derivación de claves a partir de la contraseña, autentificación en el servidor...)
- Cifrado con AES-CTR, compresión, encoding (JSON, base64), etc.

Puede servir como inspiración, pero carece mucha de la funcionalidad necesaria para la práctica.
Entre otras muchas, algunas limitaciones (por sencillez):
- Se utiliza scrypt para gestionar las contraseñas en el servidor. Argon2 es mejor opción.
- Se utiliza un token sencillo a modo de sesión/autentificación, se puede extender o hacer también con cookies (sobre HTTPS), con JWT, con firma digital, etc.
- El cliente ni es interactivo ni muy útil, es una mera demostración.

compilación:
go build

arrancar el servidor:
sdshttp srv

arrancar el cliente:
sdshttp cli

pd. Comando openssl para generar el par certificado/clave para localhost:
(ver https://letsencrypt.org/docs/certificates-for-localhost/)

	openssl req -x509 -out localhost.crt -keyout localhost.key \
	  -newkey rsa:2048 -nodes -sha256 \
	  -subj '/CN=localhost' -extensions EXT -config <( \
	   printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
*/
package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"

	"main/cliente"
	"main/server"
)

func main() {

	fmt.Println("sdshttp :: un ejemplo de login mediante TLS/HTTP en Go.")
	s := "Introduce server para funcionalidad de servidor y cliente para funcionalidad de cliente"

	connectDB()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "server":
			fmt.Println("Entrando en modo servidor...")
			server.Run()
		case "cliente":
			fmt.Println("Entrando en modo cliente...")
			cliente.Run()
		default:
			fmt.Println("Parámetro '", os.Args[1], "' desconocido. ", s)
		}
	} else {
		fmt.Println(s)
	}
}

func connectDB() {

	// Configura los detalles de conexión
	db, err := sql.Open("mysql", "root:1234@tcp(localhost:3306)/sds")
	if err != nil {
		fmt.Println(err)
	}

	// Prueba la conexión
	if err := db.Ping(); err != nil {
		fmt.Println("error al conectarse a la base de datos: %v", err)
	}

	fmt.Println(db)
}
