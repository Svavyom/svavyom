// Package console is the serial-console path of the VM recovery slice (M1-D): short-lived single-use tickets minted by the API, a
// closed broker protocol between the API and a SEPARATE, non-root console broker, the broker's per-VM serial buffer and single
// interactive attachment, and a strict minimal WebSocket server for the browser leg.
//
//	browser --WebSocket--> API (session, same-origin, ticket) --Unix socket, closed protocol--> console broker --> libvirt serial console
//
// The browser never reaches libvirt or the broker. The broker never sees a cookie, a ticket or a path: it is told "snapshot VM x" or
// "attach to VM x" by the API (peer-uid allowlist) and can do nothing else; it holds the libvirt connection, the API does not.
// There is no shell, no file read and no generic libvirt method anywhere in this package. The serial console is a full-power channel
// into the guest (the UI says so) and is off unless the operator enabled the Development Preview console switch.
package console
