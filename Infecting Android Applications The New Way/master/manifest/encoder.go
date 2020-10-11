package manifest

import (
	"encoding/xml"
	"errors"
)

// Return this error from EncodeToken to tell apkparser to finish parsing,
// to be used when you found the value you care about and don't need the rest.
var ErrEndParsing = errors.New("end manifest parsing")

// Encoder for writing the XML data. For example Encoder from encoding/xml matches this interface.
type ManifestEncoder interface {
	EncodeToken(t xml.Token) error
	Flush() error
}
