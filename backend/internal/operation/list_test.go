package operation

import (
	"fmt"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor/fake"
)

// DR-022: the operation list is newest first, continues from the id of the last item, and shows an actor only what that actor may see.
func TestListNewestFirstWithAContinuationForEveryStore(t *testing.T) {
	sq, _, _ := sqliteStore(t)
	for name, st := range map[string]Store{"mem": NewMemStore(), "sqlite": sq} {
		m := NewManager(st, fake.New(), owners{"p1": "alice"}, nil, Config{})
		var ids []string
		for i := 0; i < 5; i++ {
			ids = append(ids, mustSubmit(t, m, req(Create, fmt.Sprintf("vm-%d", i), fmt.Sprintf("k%d", i))).ID)
		}
		page, next, err := m.List(alice, 2, "")
		if err != nil || len(page) != 2 || page[0].ID != ids[4] || page[1].ID != ids[3] || next != ids[3] {
			t.Fatalf("%s first page %+v next=%q %v", name, page, next, err)
		}
		page, next, _ = m.List(alice, 2, next)
		if len(page) != 2 || page[0].ID != ids[2] || page[1].ID != ids[1] || next != ids[1] {
			t.Fatalf("%s second page %+v next=%q", name, page, next)
		}
		page, next, _ = m.List(alice, 2, next)
		if len(page) != 1 || page[0].ID != ids[0] || next != "" {
			t.Fatalf("%s last page %+v next=%q", name, page, next)
		}
		if page, next, err := m.List(alice, 2, "no-such-operation"); err != nil || len(page) != 0 || next != "" {
			t.Fatalf("%s unknown cursor %+v %q %v", name, page, next, err)
		}
		if page, _, err := m.List(Actor{ID: "mallory"}, 5, ""); err != nil || len(page) != 0 {
			t.Fatalf("%s another actor must see nothing: %+v %v", name, page, err)
		}
	}
}

type plainStore struct{ Store }

func TestListIsUnavailableOnAStoreThatCannotList(t *testing.T) {
	m := NewManager(plainStore{NewMemStore()}, fake.New(), owners{"p1": "alice"}, nil, Config{})
	if _, _, err := m.List(alice, 5, ""); CategoryOf(err) != CatUnavailable {
		t.Fatalf("%v", err)
	}
}
