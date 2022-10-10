package users

// WrongUsernameOrPasswordError is wrong login input errors
type WrongUsernameOrPasswordError struct{}

func (m *WrongUsernameOrPasswordError) Error() string {
	return "wrong username or password"
}
