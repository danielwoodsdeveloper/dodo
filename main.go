package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/sony/sonyflake"
)

var sf *sonyflake.Sonyflake

// Stores a new document
func putDocument(w http.ResponseWriter, r *http.Request) {
	var d map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&d)
	if err != nil {
		http.Error(w, "Could not decode your request. It might be invalid JSON.", http.StatusBadRequest)
		return
	}

	j, err := json.MarshalIndent(d, "", "	")
	if err != nil {
		http.Error(w, "Could not marshal your JSON request.", http.StatusInternalServerError)
		return
	}

	id, err := sf.NextID()
	if err != nil {
		http.Error(w, "Could not fetch a UID for your document.", http.StatusInternalServerError)
		return
	}

	os.Mkdir("store", 0755)
	jsonFile, err := os.Create("./store/" + strconv.FormatUint(id, 10) + ".json")
	if err != nil {
		http.Error(w, "Could not create the document file on the server.", http.StatusInternalServerError)
		return
	}
	jsonFile.Write(j)

	o := map[string]string{"id": strconv.FormatUint(id, 10)}
	js, err := json.Marshal(o)
	if err != nil {
		http.Error(w, "Could not create the response JSON.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

// Returns a single existing stored document
func getDocument(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	f, err := ioutil.ReadFile("./store/" + vars["id"] + ".json")
	if err != nil {
		http.Error(w, "Could not find or read the document store file.", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(f))
}

// Removes an existing stored document
func removeDocument(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	err := os.Remove("./store/" + vars["id"] + ".json")
	if err != nil {
		http.Error(w, "Could not remove the document store file.", http.StatusBadRequest)
		return
	}
}

// Updates an existing stored document
func modifyDocument(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	_, err := ioutil.ReadFile("./store/" + vars["id"] + ".json")
	if err != nil {
		http.Error(w, "Could not find or read the existing document store file.", http.StatusBadRequest)
		return
	}

	var d map[string]interface{}
	err = json.NewDecoder(r.Body).Decode(&d)
	if err != nil {
		http.Error(w, "Could not decode your request. It might be invalid JSON.", http.StatusBadRequest)
		return
	}

	j, err := json.MarshalIndent(d, "", "	")
	if err != nil {
		http.Error(w, "Could not marshal your JSON request.", http.StatusInternalServerError)
		return
	}

	os.Mkdir("store", 0755)
	jsonFile, err := os.Create("./store/" + vars["id"] + ".json")
	if err != nil {
		http.Error(w, "Could not create the document file on the server.", http.StatusInternalServerError)
		return
	}
	jsonFile.Write(j)
}

// Returns all stored documents
func getAllDocuments(w http.ResponseWriter, r *http.Request) {
    files, err := ioutil.ReadDir("./store")
	if err != nil {
		http.Error(w, "Could not find any document files in the store.", http.StatusInternalServerError)
		return
	}

	m := make([]map[string]interface{}, len(files))

    for i, file := range files {
		f, err := ioutil.ReadFile("./store/" + file.Name())
		if err != nil {
			http.Error(w, "Could not read one of the document store files.", http.StatusBadRequest)
			return
		}

		var d map[string]interface{}
		err = json.Unmarshal([]byte(f), &d)
		if err != nil {
			http.Error(w, "Could not decode the stored document file.", http.StatusInternalServerError)
			return
		}

		o := map[string]interface{}{"id": strings.Replace(file.Name(), ".json", "", 1), "document": d}

		m[i] = o
	}
	
	js, err := json.Marshal(m)
	if err != nil {
		http.Error(w, "Could not create the JSON response.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

// Removes all store documents
func removeAllDocuments(w http.ResponseWriter, r *http.Request) {
	err := os.RemoveAll("./store")
	if err != nil {
		http.Error(w, "Failed to remove all document store files.", http.StatusBadRequest)
		return
	}
}

type getJWTRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Validates system username and password is correct, returns JWT
func getJWT(w http.ResponseWriter, r *http.Request) {
	req := getJWTRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Could not decode your request. It might be invalid JSON.", http.StatusBadRequest)
		return
	}

	user := "admin"
	tmp, _ := os.LookupEnv("SYSTEM_USERNAME")
	if tmp != "" {
		user = tmp
	}

	pass := "VKIL3G6UZUWLM09RJ0WA"
	tmp, _ = os.LookupEnv("SYSTEM_PASSWORD")
	if tmp != "" {
		pass = tmp
	}

	salt := "5FMI7M57NZ3W083RVQVO"
	tmp, _ = os.LookupEnv("PASSWORD_SALT")
	if tmp != "" {
		salt = tmp
	}

	hash := sha256.New()
	hash.Write([]byte(pass + salt))
	md := hash.Sum(nil)
	pass = hex.EncodeToString(md)

	if user != req.Username || strings.ToUpper(pass) != strings.ToUpper(req.Password) {
		http.Error(w, "Authentication failed.", http.StatusForbidden)
		return
	}

	secret := "ASVMTBVVKGKV6RZVEL1W"
	tmp, _ = os.LookupEnv("JWT_SECRET")
	if tmp != "" {
		secret = tmp
	}

	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 3).Unix(),
	}
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, "Failed to create the JWT.", http.StatusInternalServerError)
		return
	}

	o := map[string]string{"jwt": tokenString}
	js, err := json.Marshal(o)
	if err != nil {
		http.Error(w, "Could not create the response JSON.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

// Middleware that validates JWT
func authenticate(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tmp, _ := os.LookupEnv("JWT_REQUIRED")
		if tmp == "FALSE" {
			// No JWT required, so bypass middleware
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("authorization")
		if auth == "" {
			http.Error(w, "Could not find an authorization header.", http.StatusBadRequest)
			return
		}

		s := strings.Split(auth, " ")
		if len(s) == 2 {
			token, err := jwt.Parse(s[1], func(token *jwt.Token) (interface{}, error) {
				_, ok := token.Method.(*jwt.SigningMethodHMAC)
				if !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}

				secret := "ASVMTBVVKGKV6RZVEL1W"
				tmp, _ := os.LookupEnv("JWT_SECRET")
				if tmp != "" {
					secret = tmp
				}
				
				return []byte(secret), nil
			})

			if !token.Valid {
				http.Error(w, "JWT invalid. It may be expired.", http.StatusUnauthorized)
				return
			}

			if err != nil {
				if err == jwt.ErrSignatureInvalid {
					http.Error(w, "JWT signature is invalid.", http.StatusUnauthorized)
					return
				}
				
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
		}

        next.ServeHTTP(w, r)
    })
}

func init() {
	var st sonyflake.Settings
	sf = sonyflake.NewSonyflake(st)
	if sf == nil {
		log.Fatal("Sonyflake was not created!")
		os.Exit(2)
	}
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/", authenticate(putDocument)).Methods("PUT")
	r.HandleFunc("/document/{id}", authenticate(getDocument)).Methods("GET")
	r.HandleFunc("/document/{id}", authenticate(removeDocument)).Methods("DELETE")
	r.HandleFunc("/document/{id}", authenticate(modifyDocument)).Methods("POST")
	r.HandleFunc("/all", authenticate(getAllDocuments)).Methods("GET")
	r.HandleFunc("/all", authenticate(removeAllDocuments)).Methods("DELETE")
	r.HandleFunc("/authenticate", getJWT).Methods("POST")

	log.Fatal(http.ListenAndServe(":6060", r))
}