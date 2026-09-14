// Command grant-operator makes an existing cryden user a console
// operator, or revokes that status. Deliberately a standalone
// command-line tool rather than an HTTP endpoint: an admin-bootstrap
// endpoint reachable over the network, gated or not, is a needless
// extra attack surface for something that only ever needs to happen
// from a trusted machine with direct database access.
//
// Usage:
//
//	go run ./cmd/grant-operator -db "$DATABASE_URL" -email someone@example.com
//	go run ./cmd/grant-operator -db "$DATABASE_URL" -email someone@example.com -role superadmin
//	go run ./cmd/grant-operator -db "$DATABASE_URL" -email someone@example.com -revoke
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"

	_ "github.com/lib/pq"

	"github.com/crydensync/cryden/v2/store/postgres"

	"github.com/crydensync/api/operator"
)

func main() {
	dbURL := flag.String("db", "", "DATABASE_URL (required)")
	email := flag.String("email", "", "email of the existing cryden user to grant/revoke operator status for (required)")
	role := flag.String("role", "admin", "operator role to grant (ignored with -revoke)")
	revoke := flag.Bool("revoke", false, "revoke operator status instead of granting it")
	flag.Parse()

	if *dbURL == "" || *email == "" {
		log.Fatal("usage: grant-operator -db <DATABASE_URL> -email <email> [-role <role>] [-revoke]")
	}

	db, err := sql.Open("postgres", *dbURL)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	users := postgres.NewUserStore(db)
	user, err := users.GetByEmail(ctx, *email)
	if err != nil {
		log.Fatalf("look up %s: %v (does this user exist yet? they need to sign up first)", *email, err)
	}

	operators := operator.NewStore(db)
	if *revoke {
		if err := operators.Revoke(ctx, user.ID); err != nil {
			log.Fatalf("revoke operator status for %s: %v", *email, err)
		}
		fmt.Printf("%s (%s) is no longer an operator\n", *email, user.ID)
		return
	}

	if err := operators.Grant(ctx, user.ID, *role); err != nil {
		log.Fatalf("grant operator status to %s: %v", *email, err)
	}
	fmt.Printf("%s (%s) is now an operator with role %q\n", *email, user.ID, *role)
}
