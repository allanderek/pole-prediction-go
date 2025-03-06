package main

import (
	"fmt"
	"github.com/a-h/templ"
)

func formulaOneEventUrl(eventId int64) templ.SafeURL {
	return templ.URL(fmt.Sprintf("/formulaone/event/%d", eventId))
}
