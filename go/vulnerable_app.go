package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"

	_ "github.com/go-sql-driver/mysql"
)

// Hardcoded credentials
const (
	DBPassword      = "SuperSecret123!"
	APIKey          = "sk_live_4eC39HqLyjWDarhtT657tMo5k"
	AWSAccessKey    = "AKIAIOSFODNN7EXAMPLE"
	AWSSecretKey    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	JWTSecret       = "my-jwt-secret-key"
	PrivateKey      = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6R3r4Lv7m8EqFLYrTZY...
-----END RSA PRIVATE KEY-----`
)

var db *sql.DB

func init() {
	var err error
	// Hardcoded database credentials
	db, err = sql.Open("mysql", "root:admin123@tcp(localhost:3306)/mydb")
	if err != nil {
		log.Fatal(err)
	}
}

// SQL Injection vulnerability
func getUser(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	// Vulnerable to SQL injection
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "User data retrieved")
}

// Command Injection
func pingHost(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// Vulnerable to command injection
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ping -c 1 %s", host))
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(output)
}

// Path Traversal
func readFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// Vulnerable to path traversal
	data, err := ioutil.ReadFile("/var/data/" + filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Write(data)
}

// Weak cryptography
func hashPassword(password string) string {
	// Using weak MD5
	hash := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// SSRF vulnerability
func fetchURL(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	// Vulnerable to SSRF
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}

// Insecure random number generation
func generateToken() string {
	// Using math/rand instead of crypto/rand
	import "math/rand"
	return fmt.Sprintf("%d", rand.Intn(9999))
}

// SQL Injection in authentication
func login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	
	// Vulnerable SQL injection
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'",
		username, password)
	
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Login failed", http.StatusUnauthorized)
		return
	}
	defer rows.Close()
	
	if rows.Next() {
		fmt.Fprintf(w, "Login successful")
	} else {
		fmt.Fprintf(w, "Login failed")
	}
}

// Information disclosure
func errorHandler(w http.ResponseWriter, r *http.Request) {
	err := fmt.Errorf("Database error: mysql://root:password@localhost:3306/mydb connection failed")
	// Exposing sensitive error information
	http.Error(w, err.Error(), http.StatusInternalServerError)
	log.Printf("ERROR: %v", err) // Logging sensitive data
}

// Hardcoded API key usage
func callExternalAPI() {
	url := "https://api.example.com/data?key=" + APIKey
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("API call failed: %v", err)
		return
	}
	defer resp.Body.Close()
}

// Insecure cookie settings
func setCookie(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "sensitive-data",
		HttpOnly: false, // Accessible via JavaScript
		Secure:   false, // Not HTTPS only
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(w, cookie)
}

// Unvalidated redirect
func redirect(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	// Open redirect vulnerability
	http.Redirect(w, r, url, http.StatusFound)
}

// Logging sensitive data
func processPayment(w http.ResponseWriter, r *http.Request) {
	cardNumber := r.FormValue("card")
	cvv := r.FormValue("cvv")
	// Logging sensitive payment data
	log.Printf("Processing payment: Card %s, CVV %s", cardNumber, cvv)
	fmt.Fprintf(w, "Payment processed")
}

// Unsafe file operations
func uploadFile(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// No validation on file type or content
	data, _ := ioutil.ReadAll(file)
	// Unsafe file path
	err = ioutil.WriteFile("/uploads/"+header.Filename, data, 0777)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "File uploaded")
}

// Hardcoded AWS credentials
func uploadToS3() {
	os.Setenv("AWS_ACCESS_KEY_ID", AWSAccessKey)
	os.Setenv("AWS_SECRET_ACCESS_KEY", AWSSecretKey)
	// AWS operations with hardcoded credentials
}

// Insecure TLS configuration
func createInsecureClient() *http.Client {
	import "crypto/tls"
	
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skipping certificate verification
		},
	}
	return &http.Client{Transport: tr}
}

func main() {
	http.HandleFunc("/user", getUser)
	http.HandleFunc("/ping", pingHost)
	http.HandleFunc("/file", readFile)
	http.HandleFunc("/fetch", fetchURL)
	http.HandleFunc("/login", login)
	http.HandleFunc("/error", errorHandler)
	http.HandleFunc("/cookie", setCookie)
	http.HandleFunc("/redirect", redirect)
	http.HandleFunc("/payment", processPayment)
	http.HandleFunc("/upload", uploadFile)
	
	log.Println("Starting server on :8080")
	log.Printf("Database password: %s", DBPassword) // Logging secrets
	log.Printf("API Key: %s", APIKey)
	
	// Binding to all interfaces
	if err := http.ListenAndServe("0.0.0.0:8080", nil); err != nil {
		log.Fatal(err)
	}
}
