# Upgrade Guide

## Unreleased

The module requires hesape v0.56.0, not v0.58.0. An application that went to
hesape v0.58.0 only because of this module can go back with
`go get github.com/arandu-io/hesape@v0.56.0`, which is what framework v0.56.0's
`framework/view` compiles against.

## v0.1.0

The first release. Install it with hesape v0.58.0 or newer, wire it in
`bootstrap/app.go` as the README shows, exempt `ReceivePrefix()` from the CSRF
check, add `Publisher()` to the events relay and `RegisterJobHandlers` to the
worker, run `aru migrate`, and give the people who manage webhooks the actions
of `Actions()` through arandu-permission.

