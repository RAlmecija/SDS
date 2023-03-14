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

// chk comprueba y sale si hay errores (ahorra escritura en programas sencillos)
func chk(e error) {
	if e != nil {
		panic(e)
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
	Name  string            `json:"name"`  // nombre de usuario
	Hash  []byte            `json:"hash"`  // hash de la contraseña
	Salt  []byte            `json:"salt"`  // sal para la contraseña
	Token []byte            `json:"token"` // token de sesión
	Seen  time.Time         // última vez que fue visto
	Data  map[string]string // datos adicionales del usuario
}

// respuesta del servidor
// (empieza con mayúscula ya que se utiliza en el cliente también)
// (los variables empiezan con mayúscula para que sean consideradas en el encoding)
type Resp struct {
	Ok    bool   // true -> correcto, false -> error
	Msg   string // mensaje adicional
	Token []byte // token de sesión para utilizar por el cliente
}

func guardaDatosBD(u user) {
	// Abrimos una conexión a la base de datos
	db, err := sql.Open("mysql", "root:1234@tcp(localhost:3306)/sds")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	// Preparamos la consulta SQL para insertar el usuario en la tabla users
	stmt, err := db.Prepare("INSERT INTO users (name, salt, hash, seen, token, private_key, public_key) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		panic(err.Error())
	}
	defer stmt.Close()

	// Convertimos la estructura de usuario en valores para la consulta
	salt := string(u.Salt)
	hash := string(u.Hash)
	seen := u.Seen.Format("2006-01-02 15:04:05") // Formato para MySQL DATETIME
	token := string(u.Token)

	// Ejecutamos la consulta SQL con los valores del usuario
	_, err = stmt.Exec(u.Name, salt, hash, seen, token, u.Data["private"], u.Data["public"])
	if err != nil {
		panic(err.Error())
	}
}

func existeUsuarioBD(username string) (bool, error) {
	// Abrimos una conexión a la base de datos
	db, err := sql.Open("mysql", "root:1234@tcp(localhost:3306)/sds")
	if err != nil {
		return false, err
	}
	defer db.Close()

	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE name = ?)", username).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func getUsuarioBD(username string) (*user, error) {
	// Abrimos una conexión a la base de datos
	db, err := sql.Open("mysql", "root:1234@tcp(localhost:3306)/sds")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var u user
	var seenTimeStr []uint8
	err = db.QueryRow("SELECT name, hash, salt, token, seen FROM users WHERE name = ?", username).Scan(&u.Name, &u.Hash, &u.Salt, &u.Token, &seenTimeStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("usuario no encontrado")
		}
		return nil, err
	}

	seenTime, err := time.Parse("2006-01-02 15:04:05", string(seenTimeStr))
	if err != nil {
		return nil, err
	}

	u.Seen = seenTime
	return &u, nil
}

func reloadLastSeenUser(username string) {
	// Abrimos una conexión a la base de datos
	db, err := sql.Open("mysql", "root:1234@tcp(localhost:3306)/sds")
	if err != nil {
		// Si hay un error al abrir la conexión, simplemente retornamos sin hacer nada
		return
	}
	defer db.Close()

	// Actualizamos el campo 'Seen' del usuario con el nombre 'username'
	_, err = db.Exec("UPDATE users SET seen = ? WHERE name = ?", time.Now(), username)
	if err != nil {
		// Si hay un error al actualizar el campo, simplemente retornamos sin hacer nada
		return
	}
}

// gestiona el modo servidor
func Run() {
	gPasswordEntries = make(map[string][]passwordEntry) // inicializamos mapa de entradas de contraseñas
	http.HandleFunc("/", handler)                       // asignamos un handler global

	// escuchamos el puerto 10443 con https y comprobamos el error
	chk(http.ListenAndServeTLS(":10443", "localhost.crt", "localhost.key", nil))
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "register": // ** registro
		username := req.Form.Get("user")
		exists, err := existeUsuarioBD(username)
		if err != nil {
			response(w, false, "Error al comprobar usuario en BD", nil)
			return
		}
		if exists {
			response(w, false, "Usuario ya registrado", nil)
			return
		}

		u := user{}
		u.Name = req.Form.Get("user")                   // nombre
		u.Salt = make([]byte, 16)                       // sal (16 bytes == 128 bits)
		rand.Read(u.Salt)                               // la sal es aleatoria
		u.Data = make(map[string]string)                // reservamos mapa de datos de usuario
		u.Data["private"] = req.Form.Get("prikey")      // clave privada
		u.Data["public"] = req.Form.Get("pubkey")       // clave pública
		password := util.Decode64(req.Form.Get("pass")) // contraseña

		// "hasheamos" la contraseña con scrypt (argon2 es mejor)
		u.Hash, _ = scrypt.Key(password, u.Salt, 16384, 8, 1, 32)

		u.Seen = time.Now()
		u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
		rand.Read(u.Token)         // el token es aleatorio

		guardaDatosBD(u)
		response(w, true, "Usuario registrado con éxito", nil)

	case "login": // ** inicio de sesión
		username := req.Form.Get("user")
		exists, err := existeUsuarioBD(username)
		if err != nil {
			response(w, false, "Error al comprobar usuario en BD", nil)
			return
		}
		if !exists {
			response(w, false, "Usuario no registrado", nil)
			return
		}
		u, err := getUsuarioBD(username)
		if err != nil {
			response(w, false, err.Error(), nil)
			return
		}
		password := util.Decode64(req.Form.Get("pass")) // contraseña
		hash, _ := scrypt.Key(password, u.Salt, 16384, 8, 1, 32)
		if !bytes.Equal(hash, u.Hash) { // ¿contraseña correcta?
			response(w, false, "Contraseña incorrecta", nil)
			return
		} else {
			u.Seen = time.Now()        // asignamos tiempo de login
			u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
			rand.Read(u.Token)         // el token es aleatorio
			reloadLastSeenUser(u.Name)
			response(w, true, "Credenciales válidas", u.Token)
		}

	case "data": // ** obtener datos de usuario
		username := req.Form.Get("user")
		exists, err := existeUsuarioBD(username)
		if err != nil {
			response(w, false, "Error al comprobar usuario en BD", nil)
			return
		}
		if !exists {
			response(w, false, "Usuario no registrado", nil)
			return
		}
		u, err := getUsuarioBD(username)
		if err != nil {
			response(w, false, "Error al recuperar usuario en BD", nil)
			return
		}
		if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else if !bytes.EqualFold(u.Token, util.Decode64(req.Form.Get("token"))) {
			// token no coincide
			response(w, false, "No autentificado", nil)
			return
		}

		datos, err := json.Marshal(&u.Data)
		chk(err)
		u.Seen = time.Now()
		response(w, true, string(datos), u.Token)

	default: // ** comando desconocido
		response(w, false, "Comando desconocido", nil)
	}
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string, token []byte) {
	r := Resp{Ok: ok, Msg: msg, Token: token} // formateamos respuesta
	rJSON, err := json.Marshal(&r)            // codificamos en JSON
	chk(err)                                  // comprobamos error
	w.Write(rJSON)                            // escribimos el JSON resultante
}
