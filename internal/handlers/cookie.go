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
func (h *CookieHelper) SetAuthCookies(c *gin.Context, accessToken, refreshToken string, accessExpiry, refreshExpiry time.Duration) {
	h.setCookie(c, AccessTokenCookie, accessToken, int(accessExpiry.Seconds()))
	h.setCookie(c, RefreshTokenCookie, refreshToken, int(refreshExpiry.Seconds()))
}

// ClearAuthCookies removes both authentication cookies.
func (h *CookieHelper) ClearAuthCookies(c *gin.Context) {
	h.setCookie(c, AccessTokenCookie, "", -1)
	h.setCookie(c, RefreshTokenCookie, "", -1)
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

func (h *CookieHelper) setCookie(c *gin.Context, name, value string, maxAge int) {
	c.SetSameSite(h.config.SameSite)
	c.SetCookie(
		name,
		value,
		maxAge,
		h.config.Path,
		h.config.Domain,
		h.config.Secure,
		true, // httpOnly - always true for auth cookies
	)
}
