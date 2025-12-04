package handlers

import (
	"time"

	common "github.com/GunarsK-portfolio/portfolio-common/config"
	"github.com/gin-gonic/gin"
)

const (
	// Cookie names
	AccessTokenCookie  = "access_token"
	RefreshTokenCookie = "refresh_token"

	// RefreshTokenPath restricts refresh token cookie to refresh endpoint only
	// This limits exposure surface - refresh token isn't sent with every request
	RefreshTokenPath = "/api/v1/auth/refresh" //nolint:gosec // G101: This is a URL path, not credentials
)

// CookieHelper manages authentication cookies.
type CookieHelper struct {
	config common.CookieConfig
}

// NewCookieHelper creates a new cookie helper with the given configuration.
func NewCookieHelper(config common.CookieConfig) *CookieHelper {
	return &CookieHelper{config: config}
}

// SetAuthCookies sets both access and refresh token cookies.
// Access token uses config.Path (typically "/"), refresh token uses restricted path.
func (h *CookieHelper) SetAuthCookies(c *gin.Context, accessToken, refreshToken string, accessExpiry, refreshExpiry time.Duration) {
	h.setCookie(c, AccessTokenCookie, accessToken, int(accessExpiry.Seconds()), h.config.Path)
	h.setCookie(c, RefreshTokenCookie, refreshToken, int(refreshExpiry.Seconds()), RefreshTokenPath)
}

// ClearAuthCookies removes both authentication cookies.
func (h *CookieHelper) ClearAuthCookies(c *gin.Context) {
	h.setCookie(c, AccessTokenCookie, "", -1, h.config.Path)
	h.setCookie(c, RefreshTokenCookie, "", -1, RefreshTokenPath)
}

// GetAccessToken retrieves the access token from cookie.
func (h *CookieHelper) GetAccessToken(c *gin.Context) string {
	token, err := c.Cookie(AccessTokenCookie)
	if err != nil {
		return ""
	}
	return token
}

// GetRefreshToken retrieves the refresh token from cookie.
func (h *CookieHelper) GetRefreshToken(c *gin.Context) string {
	token, err := c.Cookie(RefreshTokenCookie)
	if err != nil {
		return ""
	}
	return token
}

func (h *CookieHelper) setCookie(c *gin.Context, name, value string, maxAge int, path string) {
	c.SetSameSite(h.config.SameSite)
	c.SetCookie(
		name,
		value,
		maxAge,
		path,
		h.config.Domain,
		h.config.Secure,
		true, // httpOnly - always true for auth cookies
	)
}
