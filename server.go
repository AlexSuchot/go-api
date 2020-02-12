package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	_ "github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	"log"
	"math/rand"
	"net/http"
)

var key = securecookie.GenerateRandomKey(32)
var store = sessions.NewCookieStore([]byte(key))

var db, err = sql.Open("mysql", "Admin-go44!:Admin-go44!@tcp(localhost:3306)/go")

var clients = make(map[*websocket.Conn]bool) // connected clients
var broadcast = make(chan Message)           // broadcast channel

// Configure the upgrader
var upgrader = websocket.Upgrader{}

// Define our message object
type Message struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Message  string `json:"message"`
}

type User struct {
	// Première lettre en majuscule obligatoire pour indiquer le caractère publie (exporté) du champ
	id       int
	Username string
	Password string
	Email    string
}

func main() {

	fs := http.FileServer(http.Dir("static"))
	http.Handle("/", fs)

	if err != nil {
		panic(err.Error())
	}

	// Configure websocket route
	http.HandleFunc("/ws", handleConnections)

	// Start listening for incoming chat messages
	go handleMessages()

	http.HandleFunc("/random", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%f", rand.Float64())
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {

		// kors :
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "POST" {
			var user User
			dec := json.NewDecoder(r.Body)
			err := dec.Decode(&user)
			if err != nil {
				http.Error(w, "Bad request", http.StatusBadRequest)
			}
			var password []byte
			selectUser := db.QueryRow(`SELECT password FROM users WHERE username = ?`, user.Username)
			switch err := selectUser.Scan(&password); err {
			case nil:
				compare := bcrypt.CompareHashAndPassword(password, []byte(user.Password))
				if compare == nil {
					session, _ := store.Get(r, "auth")
					session.Values["authenticated"] = true
					session.Values["user"] = user
					session.Save(r, w)
					fmt.Fprintf(w, "Connected")

					//createToken(user, float32(2000))

				} else {
					http.Error(w, "Wrong Username or password", http.StatusBadRequest)

				}
			default:
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
		}
	})

	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "auth")
		auth, ok := session.Values["authenticated"].(bool)
		if !auth || !ok {
			http.Error(w, "Visiteur", http.StatusOK)
		} else {
			http.Error(w, "Authentifié", http.StatusOK)
		}
	})

	http.HandleFunc("/subscribe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var user User
			dec := json.NewDecoder(r.Body)
			err := dec.Decode(&user)
			if err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				fmt.Fprintf(w, "%s", err.Error())
			} else {
				if user.Username != "" && user.Password != "" && user.Email != "" {
					var clearPassword = []byte(user.Password)
					var hashPassword = hashAndSalt(clearPassword)

					// Prepare Query :
					insert, err := db.Query("INSERT INTO users (username, password, email) VALUES(?, ?, ?)", user.Username, hashPassword, user.Email) // ? = placeholder
					fmt.Fprintf(w, "User successfully created")
					http.Error(w, "User successfully created", http.StatusOK)
					if err != nil {
						panic(err.Error()) // proper error handling instead of panic in your app
					}
					defer insert.Close() // Close the statement when we leave main() / the program terminates
				}
			}
		}
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "auth")
		session.Values["authenticated"] = false
		session.Save(r, w)
		fmt.Fprintf(w, "Vous avez été deconnecté")
	})

	http.HandleFunc("/save", func(w http.ResponseWriter, r *http.Request) {

	})

	/* 	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			createToken()
		}
	}) */

	http.ListenAndServe(":1337", nil)
}

func hashAndSalt(password []byte) string {
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
	}

	return string(hash)
}

func UserExist(user User) bool {
	var username string
	err := db.QueryRow("SELECT username FROM users WHERE username = ?", user.Username).Scan(&username)
	if err != nil {
		return true
	}
	return false
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	// Upgrade initial GET request to a websocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ws.Close()

	clients[ws] = true

	for {
		var msg Message
		// Read in a new message as JSON and map it to a Message object
		err := ws.ReadJSON(&msg)
		if err != nil {
			log.Printf("error: %v", err)
			delete(clients, ws)
			break
		}
		// Send the newly received message to the broadcast channel
		broadcast <- msg
	}
}

func handleMessages() {
	for {
		// Grab the next message from the broadcast channel
		msg := <-broadcast
		// Send it out to every client that is currently connected
		for client := range clients {
			err := client.WriteJSON(msg)
			if err != nil {
				log.Printf("error: %v", err)
				client.Close()
				delete(clients, client)
			}
		}
	}
}

func createToken(user User, expirationLimit float32) string {
	token := generateSecureToken(32)
	insert, err := db.Query("INSERT INTO token(id, id_user, expiration) VALUES( ?, ?, ? )", token, user.id, expirationLimit)
	if err != nil {
		panic(err.Error())
	}
	defer insert.Close()
	log.Println(token)

	return token
}

func generateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
