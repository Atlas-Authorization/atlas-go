package atlas

import (
	"net/url"
	"strconv"
)

// Metadata is a free-form JSON object bag. The BAPI stores arbitrary JSON here
// (public_metadata, private_metadata, …).
type Metadata map[string]interface{}

// DeletedObject is the minimal acknowledgement several DELETE routes return.
type DeletedObject struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

// CursorPage is the `GET /v1/users`-style cursor page: no total, a boolean
// HasMore, and an opaque NextCursor to pass back as starting_after.
type CursorPage[T any] struct {
	Data       []T     `json:"data"`
	HasMore    bool    `json:"has_more"`
	NextCursor *string `json:"next_cursor"`
}

// ListPage is the `{ object: "list", data, has_more? }` envelope some list
// routes use (roles, sessions, oauth clients, …).
type ListPage[T any] struct {
	Object  string `json:"object"`
	Data    []T    `json:"data"`
	HasMore bool   `json:"has_more"`
}

// ListParams carries the common cursor-pagination inputs. The server clamps
// Limit to its own maximum; StartingAfter is an opaque cursor from a prior
// page's NextCursor.
type ListParams struct {
	Limit         int
	StartingAfter string
}

func (p ListParams) apply(v url.Values) {
	if p.Limit > 0 {
		v.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.StartingAfter != "" {
		v.Set("starting_after", p.StartingAfter)
	}
}

func (p ListParams) values() url.Values {
	v := url.Values{}
	p.apply(v)
	return v
}

// Iterator walks every page of a cursor-paginated list, yielding items one at a
// time and hiding the round trips. Drive it with a for loop:
//
//	it := atlas.Paginate(func(cursor string) (*atlas.CursorPage[atlas.User], error) {
//	        return c.Users.List(ctx, atlas.ListParams{StartingAfter: cursor})
//	})
//	for it.Next() {
//	        u := it.Item()
//	        // ...
//	}
//	if err := it.Err(); err != nil { ... }
type Iterator[T any] struct {
	fetch   func(startingAfter string) (*CursorPage[T], error)
	buf     []T
	cursor  string
	hasMore bool
	started bool
	current T
	err     error
}

// Paginate builds an Iterator from a fetch closure that takes the next cursor
// (empty on the first call) and returns one CursorPage.
func Paginate[T any](fetch func(startingAfter string) (*CursorPage[T], error)) *Iterator[T] {
	return &Iterator[T]{fetch: fetch, hasMore: true}
}

// Next advances to the next item, fetching another page when the buffer drains.
// It returns false when the list is exhausted or an error occurred (check Err).
func (it *Iterator[T]) Next() bool {
	if it.err != nil {
		return false
	}
	for len(it.buf) == 0 {
		if it.started && !it.hasMore {
			return false
		}
		it.started = true
		page, err := it.fetch(it.cursor)
		if err != nil {
			it.err = err
			return false
		}
		it.buf = page.Data
		it.hasMore = page.HasMore && page.NextCursor != nil
		if page.NextCursor != nil {
			it.cursor = *page.NextCursor
		}
		if len(it.buf) == 0 && !it.hasMore {
			return false
		}
	}
	it.current = it.buf[0]
	it.buf = it.buf[1:]
	return true
}

// Item returns the item the last Next call landed on.
func (it *Iterator[T]) Item() T { return it.current }

// Err returns the first error encountered while paginating, if any.
func (it *Iterator[T]) Err() error { return it.err }

// Collect drains the iterator into a single slice. Convenience for callers who
// want the whole set and accept the extra round trips.
func (it *Iterator[T]) Collect() ([]T, error) {
	var out []T
	for it.Next() {
		out = append(out, it.Item())
	}
	return out, it.Err()
}
