package delivery

import "testing"

func TestResultRefForRunIsStableAndDomainSeparated(t *testing.T) {
	first, err := ResultRefForRun("scheduled_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ResultRefForRun("scheduled_0123456789abcdef0123456789abcdef")
	if err != nil || second != first || first != "result_91487e8e778af424245e7f769f85083b" {
		t.Fatalf("unstable result ref first=%q second=%q err=%v", first, second, err)
	}
	changed, err := ResultRefForRun("scheduled_1123456789abcdef0123456789abcdef")
	if err != nil || changed == first {
		t.Fatalf("distinct run did not produce a distinct result ref: %q err=%v", changed, err)
	}
}

func TestResultRefForRunRejectsInvalidRunRef(t *testing.T) {
	for _, value := range []string{"", " leading", "native/channel/id", string([]byte{'r', 0, 'u', 'n'})} {
		if result, err := ResultRefForRun(value); err == nil || result != "" {
			t.Fatalf("ResultRefForRun(%q)=%q err=%v", value, result, err)
		}
	}
}
