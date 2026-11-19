package routing

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The changes feed (fount launch-plan M): which coordinated mailboxes changed
// since a cursor, so one coordinator can watch all of its workers in one
// request rather than polling each. Every write of the routing object bumps
// Data.Version; each mailbox record keeps the Version of the last write that
// changed it (Mailbox.Changed): new mail (its sequence), pause, lapse, keys,
// owners, entitlement, enrollment. Both are in the routing object, so the feed
// survives a reboot and is the same from every edge instance.
//
// A cursor is "<epoch>.<version>". The epoch changes when the object is restored
// from a backup (versions go back then), so a cursor from before a restore
// answers reset, and the coordinator starts over.

// ErrBadCursor means a cursor isn't one the edge hands out.
var ErrBadCursor = errors.New("routing: bad changes cursor")

// Change is one mailbox in a changes page.
type Change struct {
	MailboxID []byte
	Changed   uint64 // the routing version of its last change
	Sequence  uint64 // its last mail sequence: new mail moves it
	Paused    bool
	Lapsed    bool
}

// ChangesPage is one page of the feed.
type ChangesPage struct {
	Changes []Change
	Cursor  string // pass back for the next page
	More    bool   // more changes are waiting past Cursor
	Reset   bool   // the cursor was empty or from another epoch: this lists from the start
}

// touch marks a record as changed by the write about to persist. Caller holds
// s.mu and calls persist next; a failed persist must restore the record.
func (s *Store) touch(m *Mailbox) { m.Changed = uint64(s.data.Version + 1) }

func newEpoch() []byte {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return b
}

func (s *Store) cursor(version uint64) string {
	return hex.EncodeToString(s.data.Epoch) + "." + strconv.FormatUint(version, 10)
}

// Changes lists coordinated mailboxes changed after cursor, oldest change first,
// up to about limit (a write that changed several mailboxes isn't split across
// pages). An empty cursor, or one from before a restore, lists every coordinated
// mailbox with Reset set.
func (s *Store) Changes(cursor string, limit int) (ChangesPage, error) {
	if limit <= 0 {
		return ChangesPage{}, fmt.Errorf("routing: limit must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var after uint64
	reset := cursor == ""
	if !reset {
		epoch, ver, ok := strings.Cut(cursor, ".")
		if !ok {
			return ChangesPage{}, ErrBadCursor
		}
		e, err := hex.DecodeString(epoch)
		if err != nil {
			return ChangesPage{}, ErrBadCursor
		}
		if after, err = strconv.ParseUint(ver, 10, 64); err != nil {
			return ChangesPage{}, ErrBadCursor
		}
		if hex.EncodeToString(e) != hex.EncodeToString(s.data.Epoch) || after > uint64(s.data.Version) {
			reset, after = true, 0
		}
	}
	var all []*Mailbox
	for _, m := range s.data.Mailboxes {
		if m.Coordinated && (reset || m.Changed > after) {
			all = append(all, m)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Changed != all[j].Changed {
			return all[i].Changed < all[j].Changed
		}
		return hex.EncodeToString(all[i].MailboxID) < hex.EncodeToString(all[j].MailboxID)
	})
	page := ChangesPage{Reset: reset, Cursor: s.cursor(uint64(s.data.Version))}
	for i, m := range all {
		if i >= limit && m.Changed != all[i-1].Changed {
			page.More = true
			page.Cursor = s.cursor(all[i-1].Changed)
			break
		}
		page.Changes = append(page.Changes, Change{
			MailboxID: append([]byte(nil), m.MailboxID...),
			Changed:   m.Changed, Sequence: m.Sequence, Paused: m.Paused, Lapsed: m.Lapsed,
		})
	}
	return page, nil
}
