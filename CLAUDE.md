# CLAUDE.md - Project Guidelines for Claude

## Build, Test, and Lint Commands
* **Run Tests:** `go test -v ./...`
* **Run Specific Test:** `go test -v ./internal/auth -run TestTokenExchange`
* **Build Binary:** `make`
* **Release:** `make release-[major|minor|patch]` depending on whether we are increasing the major, minor or revision level in semantic versioning (e.g. v1.2.3)
* **Other arguments:** run m̀ake help`to get a list of available command line switches.

## Spec-Driven Development (SDD) Workflow
1. **Never code blind:** All new features or non-trivial bug fixes must have an approved specification file in the `.specs/` directory before writing implementation code.
2. **Plan first:** Always use Claude's `/plan` mode to review requirements against the codebase before editing files.
3. **Test-Driven Implementation:** Write unit or integration tests matching the acceptance criteria in the spec *before* writing the implementation code.
4. **Compliance Audit:** Before finishing a task, verify that the implementation matches the API contracts, data models, and edge cases defined in the active spec.

## Coding Style & Architecture Standards
* **Language/Framework:** Go (Golang), standard library routers or gin, Gophercloud / database/sql where applicable.
* **Error Handling:** Never swallow errors. Wrap errors using `fmt.Errorf("context: %w", err)` and return appropriate HTTP status codes mapped cleanly at the transport layer. Log errors where they occur using `log/slog`.
* **Concurrency:** Use explicit context propagation (`context.Context`) across all database calls, network requests, and background worker threads.
* **Logging:** Use structured logging (with `log/slog`) with contextual keys (`tenant_id`, `request_id`). Never log raw secrets, tokens, or PII.

## Project Structure Overview
* `cmd/` - Application entrypoints and main binaries; for details on how the application command lines are structured, see the paragraph on command line arguments
* `internal/` - Private application and library code.
* `.specs/` - Feature design documents and architectural specifications.
* 
## Command line
Each application supports command line switches.
The command line arguments parsing is based on `github.com/jessevdk/go-flags`. Where applicable, the command line follows the simple convention:
```bash
$> my-application <object> <verb>
```
where the <object> is the type of resource to act upon and <verb> is the action. This is similar to how docker works (e.g. docker image list). 