# CLAUDE.md - Assistant Guide for pole-prediction-go

## Build Commands
- Build: `go build`
- Run: `go run main.go`
- Live reload: `air` (if installed via devenv.nix)
- Tests: `go test ./...`
- Single test: `go test -v ./path/to/package -run TestName`
- Generate SQL code: `sqlc generate`
- Generate templates: `templ generate`
- DB migrations: `dbmate up`

## Code Style Guidelines
- **Imports**: Standard lib first, third-party next, project imports last
- **Naming**: CamelCase for exported, camelCase for unexported, descriptive names
- **Error handling**: Check errors, log with context, return early pattern
- **Functions**: Single responsibility, clear types, context propagation
- **Comments**: Document functions and types, mark TODOs
- **Database**: Use transactions, check query results, handle nullable values
- **Templates**: Component-based architecture with typed data passing
- **Configuration**: Environment-based with separate JSON files
- **Authentication**: Cookie-based with proper HMAC signing
- **Security**: Never log secrets, validate all user input

This codebase uses Go modules with templ for HTML templates and sqlc for database access.
We are also using tailwind for styling the HTML produced from the templates, this means that we do not have to have a lot of external styling in CSS.
