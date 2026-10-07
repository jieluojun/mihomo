# Local SMUX patch

Source: `github.com/metacubex/smux` at
`d0c8756d3141ce2c9aa1046df6a93985441c6033`
(`v0.0.0-20260105030934-d0c8756d3141`). The original license is in `LICENSE`.

`writeFrameInternal` must own the queued frame payload. A deadline, session
close, or socket error can return control to the caller while the send queue
still holds the frame. Retaining the caller's slice then races with its reuse,
including TLS record buffers returned to their pool.

The patch copies payloads before enqueueing. This preserves wire compatibility
and cancellation behavior at the cost of one allocation/copy per nonempty frame.
Remove the replacement once the upstream dependency includes an equivalent fix.

Run the local regression tests with `go test -race github.com/metacubex/smux`
from the repository root, using the application's resolved dependency versions.
The test workflow runs this module explicitly because `go test ./...` excludes
nested modules.
