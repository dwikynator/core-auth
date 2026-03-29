package delivery

import (
	"github.com/dwikynator/core-auth/internal/user"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
)

// MapUserToProto maps a user.User to an authv1.UserProfile.
func MapUserToProto(u *user.User) *authv1.UserProfile {
	p := &authv1.UserProfile{
		UserId: u.ID,
		Role:   u.Role,
	}
	if u.Email != nil {
		p.Email = *u.Email
	}
	if u.Username != nil {
		p.Username = *u.Username
	}
	if u.Phone != nil {
		p.Phone = *u.Phone
	}
	if u.EmailVerifiedAt != nil {
		p.EmailVerified = true
	}
	if u.PhoneVerifiedAt != nil {
		p.PhoneVerified = true
	}
	return p
}
