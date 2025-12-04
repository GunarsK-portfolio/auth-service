package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	common "github.com/GunarsK-portfolio/portfolio-common/config"
	"github.com/gin-gonic/gin"
)

func TestSetAuthCookies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name         string
		cookieConfig common.CookieConfig
		wantSecure   bool
		wantSameSite http.SameSite
		wantDomain   string // Go http strips leading dot from domain per RFC 6265
	}{
		{
			name: "development config",
			cookieConfig: common.CookieConfig{
				Domain:   "",
				Secure:   false,
				SameSite: http.SameSiteLaxMode,
				Path:     "/",
			},
			wantSecure:   false,
			wantSameSite: http.SameSiteLaxMode,
			wantDomain:   "",
		},
		{
			name: "production config",
			cookieConfig: common.CookieConfig{
				Domain:   ".gunarsk.com",
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
				Path:     "/",
			},
			wantSecure:   true,
			wantSameSite: http.SameSiteStrictMode,
			wantDomain:   "gunarsk.com", // Leading dot stripped by http package
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			helper := NewCookieHelper(tt.cookieConfig)
			helper.SetAuthCookies(c, "access123", "refresh456", 15*time.Minute, 7*24*time.Hour)

			cookies := w.Result().Cookies()
			if len(cookies) != 2 {
				t.Errorf("expected 2 cookies, got %d", len(cookies))
				return
			}

			var accessCookie, refreshCookie *http.Cookie
			for _, cookie := range cookies {
				if cookie.Name == "access_token" {
					accessCookie = cookie
				}
				if cookie.Name == "refresh_token" {
					refreshCookie = cookie
				}
			}

			if accessCookie == nil {
				t.Error("access_token cookie not found")
				return
			}
			if accessCookie.Value != "access123" {
				t.Errorf("access_token value = %s, want access123", accessCookie.Value)
			}
			if !accessCookie.HttpOnly {
				t.Error("access_token should be HttpOnly")
			}
			if accessCookie.Secure != tt.wantSecure {
				t.Errorf("access_token Secure = %v, want %v", accessCookie.Secure, tt.wantSecure)
			}
			if accessCookie.SameSite != tt.wantSameSite {
				t.Errorf("access_token SameSite = %v, want %v", accessCookie.SameSite, tt.wantSameSite)
			}
			if accessCookie.Path != tt.cookieConfig.Path {
				t.Errorf("access_token Path = %s, want %s", accessCookie.Path, tt.cookieConfig.Path)
			}
			if accessCookie.Domain != tt.wantDomain {
				t.Errorf("access_token Domain = %s, want %s", accessCookie.Domain, tt.wantDomain)
			}

			if refreshCookie == nil {
				t.Error("refresh_token cookie not found")
				return
			}
			if refreshCookie.Value != "refresh456" {
				t.Errorf("refresh_token value = %s, want refresh456", refreshCookie.Value)
			}
			if !refreshCookie.HttpOnly {
				t.Error("refresh_token should be HttpOnly")
			}
			if refreshCookie.Secure != tt.wantSecure {
				t.Errorf("refresh_token Secure = %v, want %v", refreshCookie.Secure, tt.wantSecure)
			}
			if refreshCookie.SameSite != tt.wantSameSite {
				t.Errorf("refresh_token SameSite = %v, want %v", refreshCookie.SameSite, tt.wantSameSite)
			}
			// Refresh token uses restricted path for security (not config.Path)
			if refreshCookie.Path != RefreshTokenPath {
				t.Errorf("refresh_token Path = %s, want %s", refreshCookie.Path, RefreshTokenPath)
			}
			if refreshCookie.Domain != tt.wantDomain {
				t.Errorf("refresh_token Domain = %s, want %s", refreshCookie.Domain, tt.wantDomain)
			}
		})
	}
}

func TestClearAuthCookies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	helper := NewCookieHelper(common.CookieConfig{Path: "/"})
	helper.ClearAuthCookies(c)

	cookies := w.Result().Cookies()
	if len(cookies) != 2 {
		t.Errorf("expected 2 cookies, got %d", len(cookies))
		return
	}

	for _, cookie := range cookies {
		if cookie.MaxAge != -1 {
			t.Errorf("Cookie %s should have MaxAge=-1, got %d", cookie.Name, cookie.MaxAge)
		}
	}
}

func TestGetTokenFromCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.AddCookie(&http.Cookie{Name: "access_token", Value: "test_token"})

	helper := NewCookieHelper(common.CookieConfig{})
	token := helper.GetAccessToken(c)

	if token != "test_token" {
		t.Errorf("GetAccessToken() = %s, want test_token", token)
	}
}

func TestGetRefreshTokenFromCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh_test"})

	helper := NewCookieHelper(common.CookieConfig{})
	token := helper.GetRefreshToken(c)

	if token != "refresh_test" {
		t.Errorf("GetRefreshToken() = %s, want refresh_test", token)
	}
}

func TestGetTokenFromCookie_Missing(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)

	helper := NewCookieHelper(common.CookieConfig{})
	token := helper.GetAccessToken(c)

	if token != "" {
		t.Errorf("GetAccessToken() = %s, want empty string", token)
	}
}
