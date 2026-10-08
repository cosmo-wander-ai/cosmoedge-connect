package inspectionlive

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionlocal"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestSanitizeLocalConnectionErrorUsesClosedNeutralVocabulary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   error
		want error
	}{
		{name: "success", in: nil, want: nil},
		{name: "credentials", in: session.ErrConnectionLoginRejected, want: inspectionlocal.ErrConnectionRejected},
		{name: "throttle", in: session.ErrConnectionLoginThrottled, want: inspectionlocal.ErrConnectionThrottled},
		{name: "unreachable", in: session.ErrConnectionLoginUnavailable, want: inspectionlocal.ErrConnectionUnavailable},
		{name: "read", in: session.ErrConnectionReadUnavailable, want: inspectionlocal.ErrConnectionReadUnavailable},
		{name: "save", in: session.ErrConnectionPersistenceFailure, want: inspectionlocal.ErrConnectionPersistenceFailed},
		{name: "unknown fails closed", in: errors.New("raw v1 response for admin at 192.168.0.22"), want: inspectionlocal.ErrConnectionRequestUnavailable},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := sanitizeLocalConnectionError(test.in)
			if test.want == nil {
				if got != nil {
					t.Fatalf("sanitizeLocalConnectionError()=%v, want nil", got)
				}
				return
			}
			if !errors.Is(got, test.want) || got.Error() != test.want.Error() {
				t.Fatalf("sanitizeLocalConnectionError()=%T %v, want %v", got, got, test.want)
			}
			projection := fmt.Sprintf("%v %+v %#v", got, got, got)
			for _, forbidden := range []string{"192.168.0.22", "admin", "raw v1"} {
				if strings.Contains(projection, forbidden) {
					t.Fatalf("neutral error leaked %q", forbidden)
				}
			}
		})
	}
}
