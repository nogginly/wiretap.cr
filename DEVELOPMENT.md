# Wiretap.cr Development

## Dependencies

1. Install [Crystal](https://crystal-lang.org/install/) 1.20.0 or later.
2. Install `ops`, either as a gem via `gem install ops_team` or with
   Homebrew via `brew tap nickthecook/crops && brew install ops`.
3. Run `ops up` to install the shards and build the `ameba` linter into
   `bin/ameba`.

## Commands

Command         |Description                                                       
----------------|------------------------------------------------------------------
`ops up`        |Install shards; build `bin/ameba` after a fresh install           
`ops test_specs`|Run the test suite (`crystal spec --order random`)                
`ops lint`      |Run `ameba` on `src/`                                             
`ops test`      |Run `ops test_specs` followed by `ops lint`; use before committing
`ops wipe`      |Clear the Crystal compiler cache                                  

To run a single spec file or example, call `crystal spec` directly, for
example `crystal spec spec/integration_spec.cr:120`.

## Tests

Integration specs in `spec/integration_spec.cr` run against a real local
`HTTP::Server` defined in `spec/support/test_server.cr`, started once per
suite on a free port. It counts requests per path, so specs can assert
whether a request reached the server or was replayed from a transcript.

## Continuous integration

GitHub Actions runs on pushes to `main` and on pull requests targeting
`main`, across Linux (x86 and ARM), macOS and Windows. It checks formatting
with `crystal tool format --check`, lints `src/` with `ameba`, and runs the
specs. Run `crystal tool format` before committing to avoid a formatting
failure.

## Contributions

See [README](./README.md).
