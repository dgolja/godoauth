package godoauth

// UserInfo generic struct holding user data info
// generic to the backend user
type UserInfo struct {
	Username string
	Password string
	Access   map[string]Priv
}
