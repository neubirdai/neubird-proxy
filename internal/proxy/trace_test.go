package proxy

import (
	"context"
	"net/http/httptrace"
	"net/textproto"
)

func withGot1xx(ctx context.Context, fn func(int, map[string][]string)) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
			fn(code, h)
			return nil
		},
	})
}
