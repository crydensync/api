// Command smoketest exercises a running `api` instance end-to-end
// over real HTTP. It does NOT start the server itself — point it at
// one that's already running:
//
//	go run . http://localhost:8080
//
// Uses a randomly generated email each run so it's safe to re-run
// against a persistent database without colliding on "user already
// exists".
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

var baseURL string

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: go run . <base-url>")
		os.Exit(1)
	}
	baseURL = os.Args[1]

	email := fmt.Sprintf("smoketest-%d@example.com", time.Now().UnixNano())
	password := "SmokeTestPass123!"

	check("health", func() error {
		var resp map[string]any
		_, err := doJSON("GET", "/v1/health", nil, "", &resp)
		return err
	})

	check("signup", func() error {
		var resp map[string]any
		status, err := doJSON("POST", "/v1/signup", map[string]string{"email": email, "password": password}, "", &resp)
		if err != nil {
			return err
		}
		if status != 201 {
			return fmt.Errorf("expected 201, got %d: %v", status, resp)
		}
		return nil
	})

	check("duplicate signup rejected", func() error {
		var resp map[string]any
		status, _ := doJSON("POST", "/v1/signup", map[string]string{"email": email, "password": password}, "", &resp)
		if status != 409 {
			return fmt.Errorf("expected 409, got %d: %v", status, resp)
		}
		return nil
	})

	var accessToken, refreshToken string
	check("login", func() error {
		var resp struct {
			Data struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
			} `json:"data"`
		}
		status, err := doJSON("POST", "/v1/login", map[string]string{"email": email, "password": password}, "", &resp)
		if err != nil {
			return err
		}
		if status != 200 {
			return fmt.Errorf("expected 200, got %d", status)
		}
		if resp.Data.AccessToken == "" || resp.Data.RefreshToken == "" {
			return fmt.Errorf("expected both tokens populated, got: %+v", resp.Data)
		}
		accessToken, refreshToken = resp.Data.AccessToken, resp.Data.RefreshToken
		return nil
	})

	check("wrong password rejected", func() error {
		var resp map[string]any
		status, _ := doJSON("POST", "/v1/login", map[string]string{"email": email, "password": "wrong"}, "", &resp)
		if status != 401 {
			return fmt.Errorf("expected 401, got %d", status)
		}
		return nil
	})

	check("verify", func() error {
		var resp map[string]any
		status, err := doJSON("GET", "/v1/verify", nil, accessToken, &resp)
		if err != nil {
			return err
		}
		if status != 200 {
			return fmt.Errorf("expected 200, got %d", status)
		}
		return nil
	})

	check("list sessions", func() error {
		var resp map[string]any
		status, err := doJSON("GET", "/v1/sessions", nil, accessToken, &resp)
		if err != nil {
			return err
		}
		if status != 200 {
			return fmt.Errorf("expected 200, got %d", status)
		}
		return nil
	})

	check("missing auth header rejected", func() error {
		var resp map[string]any
		status, _ := doJSON("GET", "/v1/sessions", nil, "", &resp)
		if status != 401 {
			return fmt.Errorf("expected 401, got %d", status)
		}
		return nil
	})

	var newRefreshToken string
	check("refresh rotation", func() error {
		var resp struct {
			Data struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
			} `json:"data"`
		}
		status, err := doJSON("POST", "/v1/refresh", map[string]string{"refresh_token": refreshToken}, "", &resp)
		if err != nil {
			return err
		}
		if status != 200 {
			return fmt.Errorf("expected 200, got %d", status)
		}
		if resp.Data.RefreshToken == refreshToken {
			return fmt.Errorf("expected a new refresh token, got the same one back")
		}
		newRefreshToken = resp.Data.RefreshToken
		return nil
	})

	check("reused (old) refresh token rejected — the property that matters most", func() error {
		var resp struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		status, err := doJSON("POST", "/v1/refresh", map[string]string{"refresh_token": refreshToken}, "", &resp)
		if err != nil {
			return err
		}
		if status != 401 || resp.Error.Code != "token_reused" {
			return fmt.Errorf("expected 401/token_reused, got %d/%s", status, resp.Error.Code)
		}
		return nil
	})

	check("session family fully revoked — even the legitimately rotated token now dead", func() error {
		var resp map[string]any
		status, _ := doJSON("POST", "/v1/refresh", map[string]string{"refresh_token": newRefreshToken}, "", &resp)
		if status == 200 {
			return fmt.Errorf("expected the rotated-forward token to also be dead after reuse detection, got 200")
		}
		return nil
	})

	fmt.Println("\nALL CHECKS PASSED")
}

func check(name string, fn func() error) {
	if err := fn(); err != nil {
		fmt.Printf("FAIL %s: %v\n", name, err)
		os.Exit(1)
	}
	fmt.Printf("OK   %s\n", name)
}

func doJSON(method, path string, body any, bearerToken string, out any) (int, error) {
	var reqBody *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reqBody = bytes.NewBuffer(b)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req, err := http.NewRequest(method, baseURL+path, reqBody)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}
