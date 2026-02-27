package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

var logger *slog.Logger
var tokenSecret []byte

func generateToken(ts int64) string {
	h := hmac.New(sha256.New, tokenSecret)
	h.Write([]byte(strconv.FormatInt(ts, 10)))
	mac := h.Sum(nil)
	return fmt.Sprintf("%d:%s", ts, base64.StdEncoding.EncodeToString(mac))
}

func validateToken(token string) bool {
	parts := strings.SplitN(token, ":", 2)
	if len(parts) != 2 {
		return false
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}

	now := time.Now().Unix()
	if ts > now || now-ts < 2 || now-ts > 900 {
		return false // too new or too old
	}

	h := hmac.New(sha256.New, tokenSecret)
	h.Write([]byte(parts[0]))
	expected := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(parts[1]))
}

func getClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if rip := r.Header.Get("X-Real-IP"); rip != "" {
		return rip
	}
	return r.RemoteAddr
}

func sendEmail(name, email, message string) error {
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USERNAME")
	smtpPass := os.Getenv("SMTP_PASSWORD")
	recipient := os.Getenv("RECIPIENT_EMAIL")

	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" || recipient == "" {
		return fmt.Errorf("missing required SMTP environment variables")
	}

	addr := smtpHost + ":" + smtpPort
	body := fmt.Sprintf("From: %s\nTo: %s\nSubject: Contact Form Submission\n\nName: %s\nEmail: %s\nMessage:\n%s",
		smtpUser, recipient, name, email, message)

	// Port 465 uses implicit TLS (SMTPS); smtp.SendMail only supports STARTTLS
	// so we must dial TLS directly and build the SMTP client ourselves.
	if smtpPort == "465" {
		tlsCfg := &tls.Config{ServerName: smtpHost}
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("tls dial: %w", err)
		}
		client, err := smtp.NewClient(conn, smtpHost)
		if err != nil {
			return fmt.Errorf("smtp client: %w", err)
		}
		defer client.Close()

		auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
		if err = client.Mail(smtpUser); err != nil {
			return fmt.Errorf("smtp MAIL FROM: %w", err)
		}
		if err = client.Rcpt(recipient); err != nil {
			return fmt.Errorf("smtp RCPT TO: %w", err)
		}
		wc, err := client.Data()
		if err != nil {
			return fmt.Errorf("smtp DATA: %w", err)
		}
		if _, err = fmt.Fprint(wc, body); err != nil {
			return fmt.Errorf("smtp write body: %w", err)
		}
		return wc.Close()
	}

	// Port 587 / 25: use STARTTLS via smtp.SendMail
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	return smtp.SendMail(addr, auth, smtpUser, []string{recipient}, []byte(body))
}

func contactHandler(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)

	if !checkAndSetCORSHeaders(w, r) {
		logger.Warn("Blocked request due to invalid origin", slog.String("origin", r.Header.Get("Origin")), slog.String("ip", ip))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		logger.Warn("Invalid HTTP method", slog.String("method", r.Method))
		return
	}

	_ = r.ParseForm()

	// check the token that was injected by the form
	token := r.FormValue("_ts_token")
	if !validateToken(token) {
		logger.Warn("Invalid or missing timestamp token", slog.String("ip", ip))
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	// honeypot fields
	if r.FormValue("_gotcha") != "" || r.FormValue("nickname") != "" {
		logger.Info("Honeypot field triggered — likely a bot", slog.String("ip", ip))
		w.WriteHeader(http.StatusOK)
		return
	}

	// real fields
	name := r.FormValue("name")
	email := r.FormValue("email")
	message := r.FormValue("message")

	if name == "" || email == "" || message == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		logger.Warn("Missing required fields", slog.String("ip", ip))
		return
	}

	err := sendEmail(name, email, message)
	if err != nil {
		http.Error(w, "Failed to send message", http.StatusInternalServerError)
		logger.Error("Failed to send email", slog.String("error", err.Error()), slog.String("ip", ip))
		return
	}

	logger.Info("Email sent successfully", slog.String("name", name), slog.String("email", email), slog.String("ip", ip))

	if next := r.FormValue("_next"); next != "" {
		http.Redirect(w, r, next, http.StatusSeeOther)
	} else {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Thanks! Your message was sent."))
	}
}

func jsTokenHandler(w http.ResponseWriter, r *http.Request) {
	ts := time.Now().Unix()
	token := generateToken(ts)

	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Cache-Control", "no-store")
	script := fmt.Sprintf(`(function () {
	const token = "%s";
	const input = document.createElement("input");
	input.type = "hidden";
	input.name = "_ts_token";
	input.value = token;
	const forms = document.querySelectorAll("form");
	forms.forEach(form => form.appendChild(input.cloneNode(true)));
})();`, token)
	_, _ = w.Write([]byte(script))
}

func checkAndSetCORSHeaders(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	allowedOrigin := os.Getenv("CORS_ALLOW_ORIGIN")
	if allowedOrigin == "" {
		allowedOrigin = "*"
	}

	// Block request if origin is not allowed
	if origin != "" && allowedOrigin != "*" && origin != allowedOrigin {
		return false
	}

	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "86400")
	}
	return true
}

func main() {
	logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// if there is an environmental variable for the token secret, use that, useful for clustering
	envSecret := os.Getenv("TOKEN_SECRET")
	if envSecret != "" {
		tokenSecret = []byte(envSecret)
		if len(tokenSecret) < 16 {
			logger.Error("TOKEN_SECRET must be at least 16 bytes")
			os.Exit(1)
		}
	} else {
		// no environmental variable, generate a token
		tokenSecret = make([]byte, 32)
		if _, err := rand.Read(tokenSecret); err != nil {
			logger.Error("Failed to generate random token secret", slog.String("error", err.Error()))
			os.Exit(1)
		}
		logger.Info("Generated ephemeral TOKEN_SECRET for this runtime")
	}

	// /f/contact endpoint is the Formspree-compatible POST endpoint
	http.HandleFunc("/f/contact", contactHandler)
	// /form-token.js returns the anti-spam JavaScript for the form
	http.HandleFunc("/form-token.js", jsTokenHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:    ":" + port,
		Handler: http.DefaultServeMux,
		ErrorLog: slog.NewLogLogger(
			slog.NewJSONHandler(os.Stdout, nil),
			slog.LevelError,
		),
	}

	logger.Info("Starting form handler", slog.String("port", port))
	err := server.ListenAndServe()
	if err != nil {
		logger.Error("Server failed", slog.String("error", err.Error()))
	}
}
