package webhook

import (
	"context"
	"fmt"

	"github.com/arandu-io/framework/security"
)

// The actions of the package. Constants rather than strings at the call site:
// a typo in an action name would silently authorize nothing, or worse,
// everything. arandu-permission fills a Subject's Actions with them.
const (
	// EndpointView is reading one endpoint, and its deliveries.
	EndpointView security.Action = "webhook.endpoint.view"
	// EndpointList is paging through the endpoints.
	EndpointList security.Action = "webhook.endpoint.list"
	// EndpointCreate is adding one.
	EndpointCreate security.Action = "webhook.endpoint.create"
	// EndpointUpdate is changing one, including turning it off.
	EndpointUpdate security.Action = "webhook.endpoint.update"
	// EndpointDelete is removing one.
	EndpointDelete security.Action = "webhook.endpoint.delete"
	// EndpointSecret is reading an endpoint's signing secret.
	EndpointSecret security.Action = "webhook.endpoint.secret"
	// EndpointTest is sending one webhook.test call to an endpoint.
	EndpointTest security.Action = "webhook.endpoint.test"

	// CallView is reading one received call.
	CallView security.Action = "webhook.call.view"
	// CallList is paging through the received calls.
	CallList security.Action = "webhook.call.list"
	// CallProcess is sending a received call to its processor again.
	CallProcess security.Action = "webhook.call.process"

	// CallReceive is storing a call whose signature checked, and CallClean
	// removing old calls. Nobody holds them: the receiver and the scheduled
	// clean issue their own Grant for the tenant the application configured,
	// and the policy refuses them to any subject.
	CallReceive security.Action = "webhook.call.receive"
	CallClean   security.Action = "webhook.call.clean"
)

// Actions are the actions a person can be given, for arandu-permission to
// offer.
func Actions() []security.Action {
	return []security.Action{
		EndpointView, EndpointList, EndpointCreate, EndpointUpdate, EndpointDelete, EndpointSecret, EndpointTest,
		CallView, CallList, CallProcess,
	}
}

// EndpointPolicy is the only authority over who does what with an Endpoint.
//
// It denies unless the subject of the endpoint's tenant carries the action.
type EndpointPolicy struct{}

// Compile-time proof that the policy answers about this entity and no other.
var _ security.Policy[Endpoint] = EndpointPolicy{}

// Can decides whether the subject may perform the action on the endpoint.
func (EndpointPolicy) Can(_ context.Context, s security.Subject, a security.Action, record Endpoint) error {
	// Tenant isolation comes first and applies to every action. The empty id
	// is the candidate that has not been stored yet, or the probe a listing
	// asks.
	if record.ID != "" && record.TenantID != s.Tenant {
		return fmt.Errorf("endpoint belongs to another tenant")
	}

	// arandu:begin custom
	if s.IsGuest() {
		return fmt.Errorf("a guest manages no endpoint")
	}
	switch a {
	case EndpointView, EndpointList, EndpointCreate, EndpointUpdate, EndpointDelete, EndpointSecret, EndpointTest:
		if s.Can(a) {
			return nil
		}
	}
	// arandu:end custom

	return fmt.Errorf("no rule allows %s on endpoint", a)
}

// CallPolicy is the only authority over who reads and reprocesses a received
// Call.
type CallPolicy struct{}

// Compile-time proof that the policy answers about this entity and no other.
var _ security.Policy[Call] = CallPolicy{}

// Can decides whether the subject may perform the action on the call.
func (CallPolicy) Can(_ context.Context, s security.Subject, a security.Action, record Call) error {
	if record.ID != "" && record.TenantID != s.Tenant {
		return fmt.Errorf("call belongs to another tenant")
	}

	// arandu:begin custom
	if s.IsGuest() {
		return fmt.Errorf("a guest reads no call")
	}
	switch a {
	case CallView, CallList, CallProcess:
		if s.Can(a) {
			return nil
		}
	}
	// arandu:end custom

	return fmt.Errorf("no rule allows %s on call", a)
}
