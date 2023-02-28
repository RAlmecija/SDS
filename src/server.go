package main

import (
    "crypto/rand"
    "encoding/base64"
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/go-pg/pg/v10"
    "github.com/go-pg/pg/v10/orm"
    "github.com/golang-jwt/jwt"
)

// Define una estructura para las credenciales de usuario
type Credential struct {
    ID       int    `json:"id"`
    UserID   int    `json:"user_id"`
    Username string `json:"username"`
    Password string `json:"password"`
}

// Define una estructura para los usuarios
type User struct {
    ID       int    `json:"id"`
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

// Define una estructura para la configuración del servidor
type Config struct {
    DBHost     string `json:"db_host"`
    DBPort     int    `json:"db_port"`
    DBUser     string `json:"db_user"`
    DBPassword string `json:"db_password"`
    DBName     string `json:"db_name"`
    JWTSecret  string `json:"jwt_secret"`
}

// Define una estructura para el servidor
type Server struct {
    router *gin.Engine
    db     *pg.DB
    config Config
}

// Inicializa el servidor
func (s *Server) Init() error {
    // Crea una conexión a la base de datos
    db := pg.Connect(&pg.Options{
        Addr:     s.config.DBHost + ":" + string(s.config.DBPort),
        User:     s.config.DBUser,
        Password: s.config.DBPassword,
        Database: s.config.DBName,
    })

    // Crea las tablas necesarias en la base de datos
    err := createSchema(db)
    if err != nil {
        return err
    }

    // Almacena la conexión a la base de datos en el servidor
    s.db = db

    // Configura el router Gin
    s.router = gin.Default()

    // Define las rutas del API
    s.router.POST("/login", s.handleLogin)
    s.router.POST("/credentials", s.handleCreateCredential)
    s.router.GET("/credentials", s.handleListCredentials)

    return nil
}

// Crea las tablas necesarias en la base de datos
func createSchema(db *pg.DB) error {
    models := []interface{}{
        (*User)(nil),
        (*Credential)(nil),
    }

    for _, model := range models {
        err := db.Model(model).CreateTable(&orm.CreateTableOptions{
            Temp: true,
        })
        if err != nil {
            return err
}
return nil
}

// Maneja la solicitud de inicio de sesión
func (s *Server) handleLogin(c *gin.Context) {
    // Parsea las credenciales del cuerpo de la solicitud
    var credential Credential
    if err := c.ShouldBindJSON(&credential); err != nil {
        c.JSON(http.StatusBadRequest, ErrorResponse{Message: "Credenciales inválidas"})
        return
    }

    // Busca el usuario correspondiente en la base de datos
    user := &User{}
    err := s.db.Model(user).Where("username = ?", credential.Username).Select()
    if err != nil {
        c.JSON(http.StatusBadRequest, ErrorResponse{Message: "Credenciales inválidas"})
        return
    }

    // Verifica la contraseña del usuario
    if user.Password != credential.Password {
        c.JSON(http.StatusBadRequest, ErrorResponse{Message: "Credenciales inválidas"})
        return
    }

    // Crea un token de acceso para el usuario
    token := jwt.New(jwt.SigningMethodHS256)
    claims := token.Claims.(jwt.MapClaims)
    claims["user_id"] = user.ID
    accessToken, err := token.SignedString([]byte(s.config.JWTSecret))
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{Message: "Error al crear el token"})
        return
    }

    // Retorna el token de acceso al cliente
    c.JSON(http.StatusOK, Token{AccessToken: accessToken})
}

// Maneja la solicitud de creación de credenciales de usuario
func (s *Server) handleCreateCredential(c *gin.Context) {
    // Parsea las credenciales del cuerpo de la solicitud
    var credential Credential
    if err := c.ShouldBindJSON(&credential); err != nil {
        c.JSON(http.StatusBadRequest, ErrorResponse{Message: "Credenciales inválidas"})
        return
    }

    // Crea una nueva credencial en la base de datos
    _, err := s.db.Model(&credential).Returning("*").Insert()
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{Message: "Error al crear la credencial"})
        return
    }

    // Retorna la nueva credencial al cliente
    c.JSON(http.StatusOK, credential)
}

// Maneja la solicitud de listar todas las credenciales de usuario
func (s *Server) handleListCredentials(c *gin.Context) {
    // Obtiene todas las credenciales de la base de datos
    credentials := []Credential{}
    err := s.db.Model(&credentials).Select()
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{Message: "Error al obtener las credenciales"})
        return
    }

    // Retorna todas las credenciales al cliente
    c.JSON(http.StatusOK, credentials)
}
