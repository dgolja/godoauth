package godoauth

import (
	"bytes"
	"reflect"
	"testing"
)

var vaultReturnV_1 = `
{  
   "lease_id":"registry/foo/ed5d260f-8461-1c32-70af-04fac57c56fe",
   "renewable":false,
   "lease_duration":2592000,
   "data":{  
      "access":"repository:foo/bar:*",
      "password":"bar"
   },
   "auth":null
}
`

var vaultInvalidReturnV_1 = `
{  
   "lease_id":"registry/foo/ed5d260f-8461-1c32-70af-04fac57c56fe",
   "renewable":false,
   "lease_duration":2592000,
   "data":{  
      "access":"foo/bar:*",
      "password":"bar"
   },
   "auth":null
}
`

func TestUnmarshalText(t *testing.T) {
	v := &VaultClient{}

	access := make(map[string]Priv)
	access["foo/bar"] = PrivAll

	r, err := v.UnmarshalText(bytes.NewBuffer([]byte(vaultReturnV_1)))

	if err != nil {
		t.Errorf("unexpected error %s", err)
	}

	if r.Password != "bar" {
		t.Errorf("Expected password bar, but received %s", r.Password)
	}

	if !reflect.DeepEqual(r.Access, access) {
		t.Errorf("Expected same value between %v and %v", r.Access, access)
	}

	if _, err := v.UnmarshalText(bytes.NewBuffer([]byte(vaultInvalidReturnV_1))); err == nil {
		t.Errorf("Expected error for %s", vaultInvalidReturnV_1)
	}

}
