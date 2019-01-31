package main

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	mongo "gopkg.in/go-oauth2/mongo.v3"

	_ "github.com/lib/pq"

	"github.com/go-session/session"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
)

type User struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type UserMini struct {
	ID        int    `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type UserMax struct {
	ID        int    `json:"id"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type Response struct {
	Data map[string]int `json:"data"`
}

type ErrorResponse struct {
	Error map[string]string `json:"error"`
}

type UsersList struct {
	Count int        `json:"count"`
	Data  []UserMini `json:"data"`
}

type GetUser struct {
	Count int      `json:"count"`
	Data  UserMini `json:"data"`
}

// Write gzipped data to a Writer
func gzipWrite(w http.ResponseWriter, data []byte) []byte {
	w.Header().Add("Accept-Charset", "utf-8")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "gzip")
	var b bytes.Buffer
	gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		errorResponse(w, err.Error())
	}
	if _, err := gz.Write(data); err != nil {
		errorResponse(w, err.Error())
	}
	if err := gz.Flush(); err != nil {
		errorResponse(w, err.Error())
	}
	if err := gz.Close(); err != nil {
		errorResponse(w, err.Error())
	}
	return []byte(b.String())
}

func main() {
	connectionString := "user=postgres password=1369s1r3d69 dbname=oauth"
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	// manager.MustTokenStorage(store.NewMemoryTokenStore())
	manager.MapTokenStorage(
		mongo.NewTokenStore(mongo.NewConfig(
			"mongodb://127.0.0.1:27017",
			"oauth2",
		)),
	)

	clientStore := store.NewClientStore()
	clientStore.Set("222222", &models.Client{
		ID:     "222222",
		Secret: "22222222",
		Domain: "http://localhost:9094",
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)
	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	//http.Handle("/assets/", http.FileServer(http.Dir("static/assets/")))
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("static/assets"))))

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/users/", usersHandler)
	http.HandleFunc("/auth", authHandler)

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		store, err := session.Start(nil, w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var form url.Values
		if v, ok := store.Get("ReturnUri"); ok {
			form = v.(url.Values)
		}
		r.Form = form

		store.Delete("ReturnUri")
		store.Save()

		err = srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    token.GetUserID(),
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(data)
	})

	http.HandleFunc("/token-info", func(w http.ResponseWriter, r *http.Request) {
		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		connectionString := "user=postgres password=1369s1r3d69 dbname=oauth sslmode=disable"
		db, err := sql.Open("postgres", connectionString)
		if err != nil {
			log.Fatal(err)
		}

		hexString := hex.EncodeToString([]byte(token.GetUserID()))

		userId, err := strconv.ParseInt(hexString, 16, 0)
		if err != nil {
			errorResponse(w, err.Error())
			return
		}

		user := UserMini{}
		err = db.QueryRow(fmt.Sprintf("SELECT id, email, first_name, last_name FROM users WHERE id = %v", userId)).Scan(&user.ID, &user.Email, &user.FirstName, &user.LastName)
		if err != nil {
			errorResponse(w, err.Error())
		}

		data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    userId,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
		}

		jsonResponse, _ := json.Marshal(data)

		w.Write(gzipWrite(w, jsonResponse))
	})

	log.Println("Server is running at 9096 port.")
	log.Fatal(http.ListenAndServe(":9096", nil))
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	store, err := session.Start(nil, w, r)
	if err != nil {
		return
	}

	uid, ok := store.Get("LoggedInUserID")
	if !ok {
		if r.Form == nil {
			r.ParseForm()
		}

		store.Set("ReturnUri", r.Form)
		store.Save()

		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	userID = uid.(string)
	store.Delete("LoggedInUserID")
	store.Save()
	return
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	store, err := session.Start(nil, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		connectionString := "user=postgres password=1369s1r3d69 dbname=oauth sslmode=disable"
		db, err := sql.Open("postgres", connectionString)
		if err != nil {
			log.Fatal(err)
		}

		user := UserMax{}
		userError := db.QueryRow("SELECT * FROM users WHERE email = $1", username).Scan(&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName)
		if userError != nil {
			errorResponse(w, userError.Error())
			return
		}

		if comparePasswords(user.Password, []byte(password)) {
			store.Set("LoggedInUserID", string(user.ID))
			store.Save()

			w.Header().Set("Location", "/auth")
			w.WriteHeader(http.StatusFound)
		} else {
			errorResponse(w, "Invalid username / password")
		}
		return
	}
	outputHTML(w, r, "static/login.html")
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	store, err := session.Start(nil, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := store.Get("LoggedInUserID"); !ok {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	outputHTML(w, r, "static/auth.html")
}

func outputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	fi, _ := file.Stat()
	http.ServeContent(w, req, file.Name(), fi.ModTime(), file)
}

func hashAndSalt(pwd []byte) string {

	// Use GenerateFromPassword to hash & salt pwd
	// MinCost is just an integer constant provided by the bcrypt
	// package along with DefaultCost & MaxCost.
	// The cost can be any value you want provided it isn't lower
	// than the MinCost (4)
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	// GenerateFromPassword returns a byte slice so we need to
	// convert the bytes to a string and return it
	return string(hash)
}

func comparePasswords(hashedPwd string, plainPwd []byte) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		id := strings.TrimPrefix(r.URL.Path, "/users/")
		connectionString := "user=postgres password=1369s1r3d69 dbname=oauth sslmode=disable"
		db, err := sql.Open("postgres", connectionString)
		if err != nil {
			log.Fatal(err)
		}

		if id == "" {
			rows, err := db.Query("SELECT * FROM users")
			if err != nil {
				errorResponse(w, err.Error())
			}
			defer rows.Close()

			usersList := make([]UserMini, 0)
			var password string
			for rows.Next() {
				user := UserMini{}
				err := rows.Scan(&user.ID, &user.Email, &password, &user.FirstName, &user.LastName)
				if err != nil {
					errorResponse(w, err.Error())
					return
				}
				usersList = append(usersList, user)
			}
			fmt.Println(usersList)

			usersResponse := UsersList{len(usersList), usersList}

			jsonResponse, _ := json.Marshal(usersResponse)
			w.Write(gzipWrite(w, jsonResponse))
		} else {
			user := UserMini{}
			err := db.QueryRow(fmt.Sprintf("SELECT id, email, first_name, last_name FROM users WHERE id = %s", id)).Scan(&user.ID, &user.Email, &user.FirstName, &user.LastName)
			if err != nil {
				errorResponse(w, err.Error())
			}

			userResponse := GetUser{Count: 1, Data: user}

			jsonResponse, _ := json.Marshal(userResponse)
			w.Write(gzipWrite(w, jsonResponse))
		}
		break
	case "POST":
		connectionString := "user=postgres password=1369s1r3d69 dbname=oauth sslmode=disable"
		db, err := sql.Open("postgres", connectionString)
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		if err := r.ParseForm(); err != nil {
			//fmt.Fprintf(w, "ParseForm() err: %v", err)
			errorResponse(w, err.Error())
			return
		}
		// fmt.Fprintf(w, "Post from website! r.PostFrom = %v\n", r.PostForm)

		var user User
		user.Email = r.PostFormValue("email")
		user.Password = r.PostFormValue("password")
		user.FirstName = r.PostFormValue("first_name")
		user.LastName = r.PostFormValue("last_name")

		fmt.Println(hashAndSalt([]byte(user.Password)))

		var id int
		err = db.QueryRow(fmt.Sprintf("INSERT INTO users(email, password, first_name, last_name) VALUES ('%s', '%s', '%s', '%s') RETURNING id", user.Email, hashAndSalt([]byte(user.Password)), user.FirstName, user.LastName)).Scan(&id)

		if err != nil {
			errorResponse(w, err.Error())
			return
		}

		response := Response{}
		response.Data = map[string]int{"id": id}
		jsonResponse, _ := json.Marshal(response)
		w.Write(gzipWrite(w, jsonResponse))
	}
}

func errorResponse(w http.ResponseWriter, message string) {
	error := ErrorResponse{map[string]string{"message": message}}
	responseJson, _ := json.Marshal(error)
	w.Header().Set("Content-type", "application/json")
	w.Write(responseJson)
}
