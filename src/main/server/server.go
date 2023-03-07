package server

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"main/util"
	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/scrypt"
)

// use forward slash as path separator
// escape the backslash with another backslash

// chk comprueba y sale si hay errores (ahorra escritura en programas sencillos)
func chk(e error) {
	if e != nil {
		panic(e)
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
}

// ejemplo de tipo para una entrada de contraseñas
type passwordEntry struct {
	ID       string `json:"id"`       // identificador
	Username string `json:"username"` // usuario
	Password string `json:"password"` // contraseña
}

// mapa con todas las entradas de contraseñas de los usuarios
var gPasswordEntries map[string][]passwordEntry

// mapa con todos los usuarios
type user struct {
	Name       string `json:"name"`        // nombre de usuario
	Hash       []byte `json:"hash"`        // hash de la contraseña
	Salt       []byte `json:"salt"`        // sal para la contraseña
	Token      []byte `json:"token"`       // token de sesión
	LastActive int64  `json:"last_active"` // última vez que se usó el token
}

// mapa con todos los usuarios
var gUsers map[string]user

// gestiona el modo servidor
func Run() {
	gUsers = make(map[string]user)                      // inicializamos mapa de usuarios
	gPasswordEntries = make(map[string][]passwordEntry) // inicializamos mapa de entradas de contraseñas
	connectDB()
	http.HandleFunc("/", handler)                // asignamos un handler global
	http.HandleFunc("/register", handleRegister) //asignamos un handler register

	// escuchamos el puerto 10443 con https y comprobamos el error
	chk(http.ListenAndServe(":8080", https))
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	// verifica si el método de solicitud es POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// extrae los campos de nombre de usuario y contraseña del formulario
	username := r.FormValue("username")
	password := r.FormValue("password")

	// comprueba si el nombre de usuario ya está registrado
	if _, ok := gUsers[username]; ok {
		response(w, false, "El usuario ya está registrado", nil)
		return
	}

	// crea un nuevo usuario con el nombre de usuario y la contraseña especificados
	u := user{}
	u.Name = username
	u.Salt = make([]byte, 16)
	rand.Read(u.Salt)
	hash, err := scrypt.Key([]byte(password), u.Salt, 16384, 8, 1, 32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u.Hash = hash
	u.Token = make([]byte, 16)
	rand.Read(u.Token)
	u.LastActive = time.Now().Unix()

	// agrega el nuevo usuario al mapa global de usuarios
	gUsers[u.Name] = u

	response(w, true, "Registro exitoso", nil)
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "register": // ** registro
		_, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if ok {
			response(w, false, "Usuario ya registrado", nil)
			return
		}

		u := user{}
		u.Name = req.Form.Get("user")                   // nombre
		u.Salt = make([]byte, 16)                       // sal (16 bytes == 128 bits)
		rand.Read(u.Salt)                               // la sal es aleatoria
		password := util.Decode64(req.Form.Get("pass")) // contraseña

		// "hasheamos" la contraseña con scrypt (argon2 es mejor)
		u.Hash, _ = scrypt.Key(password, u.Salt, 16384, 8, 1, 32)

		u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
		rand.Read(u.Token)         // el token es aleatorio
		u.LastActive = time.Now().Unix()

		gUsers[u.Name] = u // añadimos al nuevo usuario al mapa global de usuarios
		response(w, true, "Usuario registrado con éxito", nil)

	case "login": // ** inicio de sesión
		u, ok := gUsers[req.Form.Get("user")] // comprobamos si el usuario existe
		if !ok {
			response(w, false, "Usuario no registrado", nil)
			return
		}

		password := util.Decode64(req.Form.Get("pass")) // contraseña
		hash, _ := scrypt.Key(password, u.Salt, 16384, 8, 1, 32)

		if !bytes.Equal(hash, u.Hash) { // ¿contraseña correcta?
			response(w, false, "Contraseña incorrecta", nil)
			return
		}

		token := make([]byte, 16) // nuevo token de sesión
		rand.Read(token)          // aleatorio
		u.Token = token
		u.LastActive = time.Now().Unix()

		tokenMap := map[string]string{"token": fmt.Sprintf("%x", token)}
		tokenBytes, err := json.Marshal(tokenMap)
		if err != nil {
			// manejo de error
		}
		response(w, true, "Inicio de sesión correcto", tokenBytes)

	default: // ** comando desconocido
		response(w, false, "Comando desconocido", nil)
	}
}

// respuesta del servidor
// (empieza con mayúscula ya que se utiliza en el cliente también)
// (los variables empiezan con mayúscula para que sean consideradas en el encoding)
type Resp struct {
	Ok    bool   // true -> correcto, false -> error
	Msg   string // mensaje adicional
	Token []byte // token de sesión para utilizar por el cliente
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string, token []byte) {
	r := Resp{Ok: ok, Msg: msg, Token: token} // formateamos respuesta
	rJSON, err := json.Marshal(&r)            // codificamos en JSON
	chk(err)                                  // comprobamos error
	w.Write(rJSON)                            // escribimos el JSON resultante
}
