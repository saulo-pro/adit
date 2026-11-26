package api

import "os/user"

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "YOUR-USER"
}
