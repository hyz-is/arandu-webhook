# Upgrade Guide

## Unreleased

## v0.1.0

The first release. Install it with hesape v0.58.0 or newer, wire it in
`bootstrap/app.go` as the README shows, exempt `ReceivePrefix()` from the CSRF
check, add `Publisher()` to the events relay and `RegisterJobHandlers` to the
worker, run `aru migrate`, and give the people who manage webhooks the actions
of `Actions()` through arandu-permission.

