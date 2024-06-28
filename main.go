package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var (
	db    *sql.DB
	store = sessions.NewCookieStore([]byte("super-secret-key"))
)

func connectDb() {
	dbPath := "./reviewer.db"

	var err error

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Fatal(err)
	}
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		http.ServeFile(w, r, "register.html")
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users(username, password) VALUES(?, ?)", username, hashedPassword)
		if err != nil {
			http.Error(w, "Username already taken", http.StatusBadRequest)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		http.ServeFile(w, r, "login.html")
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var storedPassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Invalid username or password", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Set session
		session, _ := store.Get(r, "session-name")
		session.Values["authenticated"] = true
		// Redirect to original URL or default to /
		originalURL := session.Values["originalURL"]
		delete(session.Values, "originalURL")
		session.Save(r, w)

		if originalURL != nil {
			http.Redirect(w, r, originalURL.(string), http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/protected", http.StatusSeeOther)
		}
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = false
	session.Save(r, w)
	fmt.Println(session.Values)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func setNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // HTTP 1.1
	w.Header().Set("Pragma", "no-cache")                                   // HTTP 1.0
	w.Header().Set("Expires", "0")                                         // Proxies
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		fmt.Println(session.Values)
		auth, ok := session.Values["authenticated"].(bool)
		if !ok || !auth {
			session.Values["originalURL"] = r.URL.Path
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		setNoCacheHeaders(w)
		next.ServeHTTP(w, r)
	})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("In Protected Handler")
	session, _ := store.Get(r, "session-name")
	fmt.Println(session.Values)
	http.ServeFile(w, r, "protected.html")
}

func superProtectedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("In super Protected Handler")
	session, _ := store.Get(r, "session-name")
	fmt.Println(session.Values)
	http.ServeFile(w, r, "superprotected.html")
}

func main() {
	connectDb()
	defer db.Close()

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	protected := http.HandlerFunc(protectedHandler)
	http.Handle("/protected", authMiddleware(protected))

	superProtected := http.HandlerFunc(superProtectedHandler)
	http.Handle("/superprotected", authMiddleware(superProtected))

	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
