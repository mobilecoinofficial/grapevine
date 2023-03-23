mc-bomb-connection
==================

This rust connection object can make attested connections to the mc-bomb-server,
and make encrypted CRUD requests.

This object might be appropriate to use directly in rust code, but if you are making
a mobile app, you likely aren't using rust, and you then don't want to bind directly
to this, because it contains `grpcio` connections. You likely want to use a native
grpc library in your language instead.

This is mainly meant to serve as example / test code that shows how to form the
attested connection, sign the challenges, and make encrypted requests.
