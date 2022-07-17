tailscale-cert-jks-updater
===

This is a small application that updates a JKS keystore with the cert from Tailscale, so that your Java application can use it. When run it will fetch the certificate from Tailscale, and compare it to the one in the specified JKS keystore - if they differ it will update the jks keystore with the new cert, and optionally run a command (to reload the server or similar).

It must be run either as `root` or a user that has access to Tailscale's socket, see [the documentation for Caddy](https://tailscale.com/kb/1190/caddy-certificates/#provide-non-root-users-with-access-to-fetch-certificate).


The (reload) command will only be run when the certificate is updated, so it can be run frequently without the application reloading unnecessary.

Example command:

```
tailscale-cert-jks-updater --keystore my_keystore.jks --storepass my_password --alias my_cert --domain my-server.example.ts.net --command "pkill -f MY_PROC -SIGHUP"
```


This is obviously not a Tailscale product, so it may break at any time if they change anything.
