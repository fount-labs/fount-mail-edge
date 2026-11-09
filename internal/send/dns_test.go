package send

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func dohServer(t *testing.T, answers map[string]string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/dns-json" {
			http.Error(w, "accept", http.StatusBadRequest)
			return
		}
		body, ok := answers[r.URL.Query().Get("name")+"/"+r.URL.Query().Get("type")]
		if !ok {
			body = `{"Status":3}`
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestDoHAgreement(t *testing.T) {
	mx := `{"Status":0,"Answer":[{"name":"smithcpa.com.","type":15,"data":"20 alt.smithcpa.com."},{"name":"smithcpa.com.","type":15,"data":"10 MX.smithcpa.com."}]}`
	mxOtherOrder := `{"Status":0,"Answer":[{"name":"smithcpa.com.","type":15,"data":"10 MX.smithcpa.com."},{"name":"smithcpa.com.","type":15,"data":"20 alt.smithcpa.com."}]}`
	forged := `{"Status":0,"Answer":[{"name":"smithcpa.com.","type":15,"data":"10 evil.example."}]}`
	txt := `{"Status":0,"Answer":[{"name":"x.","type":5,"data":"y."},{"name":"y.","type":16,"data":"\"v=STSv1; \" \"id=42\""}]}`

	a := dohServer(t, map[string]string{"smithcpa.com/15": mx, "_mta-sts.smithcpa.com/16": txt})
	b := dohServer(t, map[string]string{"smithcpa.com/15": mxOtherOrder, "_mta-sts.smithcpa.com/16": txt})
	c := dohServer(t, map[string]string{"smithcpa.com/15": forged})
	ctx := context.Background()

	d := &DoH{Client: http.DefaultClient, Endpoints: []string{a, b}}
	got, err := d.MX(ctx, "smithcpa.com")
	if err != nil || len(got) != 2 || got[0] != (MX{10, "mx.smithcpa.com"}) || got[1].Host != "alt.smithcpa.com" {
		t.Fatalf("MX = %+v, %v", got, err)
	}
	txts, err := d.TXT(ctx, "_mta-sts.smithcpa.com")
	if err != nil || len(txts) != 1 || txts[0] != "v=STSv1; id=42" {
		t.Fatalf("TXT = %q, %v", txts, err)
	}
	if _, err := d.MX(ctx, "nothing.example"); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("NXDOMAIN: %v", err)
	}

	d = &DoH{Client: http.DefaultClient, Endpoints: []string{a, c}}
	if _, err := d.MX(ctx, "smithcpa.com"); err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("disagreeing resolvers: %v", err)
	}
	if _, err := (&DoH{Client: http.DefaultClient, Endpoints: []string{a}}).MX(ctx, "smithcpa.com"); err == nil {
		t.Fatal("one resolver was enough")
	}
}

func TestParseSTSPolicy(t *testing.T) {
	p, err := ParseSTSPolicy(strings.NewReader("version: STSv1\r\nmode: enforce\r\nmx: mx.smithcpa.com\r\nmx: *.mail.example.net\r\nmax_age: 604800\r\nextra: ignored\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"mx.smithcpa.com":       true,
		"MX.smithcpa.com.":      true,
		"a.mail.example.net":    true,
		"a.b.mail.example.net":  false,
		"mail.example.net":      false,
		"evil.example":          false,
		"mx.smithcpa.com.evil.": false,
	} {
		if p.Allows(host) != want {
			t.Errorf("Allows(%q) = %v", host, !want)
		}
	}
	testing_, _ := ParseSTSPolicy(strings.NewReader("version: STSv1\nmode: testing\nmax_age: 1\n"))
	if !testing_.Allows("anything.example") {
		t.Error("testing mode filtered an MX")
	}
	var none *STSPolicy
	if !none.Allows("x") {
		t.Error("nil policy filtered an MX")
	}
	for _, bad := range []string{
		"mode: enforce\nmx: a.b\nmax_age: 1\n",
		"version: STSv2\nmode: enforce\nmx: a.b\nmax_age: 1\n",
		"version: STSv1\nmode: strict\nmx: a.b\nmax_age: 1\n",
		"version: STSv1\nmode: enforce\nmax_age: 1\n",
		"version: STSv1\nmode: enforce\nmx: a.b\n",
	} {
		if _, err := ParseSTSPolicy(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSTSID(t *testing.T) {
	if id, ok := stsID([]string{"v=spf1 -all", "v=STSv1; id=20261108"}); !ok || id != "20261108" {
		t.Fatalf("%q %v", id, ok)
	}
	if _, ok := stsID([]string{"v=STSv1; id=1", "v=STSv1; id=2"}); ok {
		t.Fatal("two records counted as one policy")
	}
}

func FuzzParseSTSPolicy(f *testing.F) {
	f.Add("version: STSv1\nmode: enforce\nmx: *.a.b\nmax_age: 5\n")
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseSTSPolicy(strings.NewReader(s))
		if err != nil {
			return
		}
		if p.Mode == STSEnforce && len(p.MX) == 0 {
			t.Fatal("enforce policy with no MX")
		}
	})
}
