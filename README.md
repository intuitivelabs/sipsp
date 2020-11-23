# sipsp

This go modules provides SIP message "stream" parsing functions.

It supports parsing partial SIP messages received on streams: if the
parsing functions detect an incomplete message, they will signal
this through the return values and parsing can be latter resumed
fromt the point where it stopped.
