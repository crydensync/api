package usermeta

import (
	"context"

	"github.com/crydensync/cryden/v2/token"
)

// RoleLookup is what the claims provider needs to know about console
// operators. operator.Store satisfies it as it stands, and it is declared
// here rather than imported so this package keeps its one dependency —
// the claim names — and does not reach into a sibling package for a
// single method.
type RoleLookup interface {
	RoleFor(ctx context.Context, userID string) (role string, isOperator bool, err error)
}

// ClaimsProvider builds the token.ClaimsProvider that main.go wires into
// cryden.Config.AccessTokenClaims: every metadata key set on the user,
// plus "role" for an operator.
//
// It is a function in this package rather than a closure written inline
// in main.go for one reason — a closure in package main cannot be
// reached by a test, and the merge is the half of this feature that
// storage tests cannot prove. Asserting that a stored key reaches a real
// token is only meaningful if the code under test is the code that runs
// in production, not a copy of it written next to the assertion.
//
// Two properties worth stating, because both are load-bearing:
//
//   - A user with no metadata who is not an operator gets NO claims at
//     all — nil, not an empty map. The absence of a "role" claim is what
//     RequireAdmin reads as "ordinary user" (see middleware.go).
//   - "role" is written after the metadata, so it always wins the map.
//     That is a second line of defence and nothing more: the real rule
//     is that Set refuses "role" as a key (see RoleClaim), because a
//     merge order is a guarantee that lasts until someone reorders two
//     statements.
//
// operators may be nil for a host with no operator table at all, in which
// case every user's claims are their metadata alone.
func ClaimsProvider(meta Store, operators RoleLookup) token.ClaimsProvider {
	return token.ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
		var (
			role       string
			isOperator bool
		)
		if operators != nil {
			var err error
			role, isOperator, err = operators.RoleFor(ctx, userID)
			if err != nil {
				return nil, err
			}
		}

		mapped, err := meta.AllFor(ctx, userID)
		if err != nil {
			return nil, err
		}
		if !isOperator && len(mapped) == 0 {
			return nil, nil
		}

		claims := make(map[string]any, len(mapped)+1)
		for key, value := range mapped {
			claims[key] = value
		}
		if isOperator {
			claims[RoleClaim] = role
		}
		return claims, nil
	})
}
