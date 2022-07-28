import os
import sys
from pathlib import Path
from typing import List, Optional

import click
import httpx
import jks
import pem
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class TailscaleClient:
    TAILSCALE_SOCKET = "/run/tailscale/tailscaled.sock"
    TAILSCALE_CERT_URL = "http://./localapi/v0/cert/{}"
    TIMEOUT = 600.0  # initial cert retrival can take a while

    def __init__(self, client: httpx.Client, url: str):
        self.client = client
        self.url = url

    @classmethod
    def create(cls, domain: str):
        client = httpx.Client(
            transport=httpx.HTTPTransport(uds=cls.TAILSCALE_SOCKET), timeout=cls.TIMEOUT
        )
        url = cls.TAILSCALE_CERT_URL.format(domain)
        return cls(client, url)

    def get_certs(self):
        response = self.client.get(self.url, params={"type": "cert"})
        response.raise_for_status()
        pem_certs = pem.parse(response.content)

        certs: List[x509.Certificate] = []
        for pem_cert in pem_certs:
            if isinstance(pem_cert, pem.Certificate):
                certs.append(x509.load_pem_x509_certificate(pem_cert.as_bytes()))
            else:
                raise NotImplementedError(
                    f"Unexpected PEM type returned from Tailscale: {type(pem_cert)}"
                )
        return certs

    def get_key(self):
        response = self.client.get(self.url, params={"type": "key"})
        response.raise_for_status()
        pem_keys = pem.parse(response.content)

        if len(pem_keys) != 1:
            raise Exception(
                f"Unexpected amount of keys returned from Tailscale: {len(pem_keys)}"
            )
        [pem_key] = pem_keys

        if not isinstance(pem_key, pem.Key):
            raise NotImplementedError(
                f"Unexpected PEM type returned from Tailscale: {type(pem_key)}"
            )
        return serialization.load_pem_private_key(
            pem_key.as_bytes(),
            password=None,
        )


@click.command()
@click.option("--keystore", required=True, help="Keystore to update.")
@click.option("--storepass", required=True, help="Password for the keystore")
@click.option("--keypass", help="Password for the key entry")
@click.option("--alias", required=True, help="Alias for the key entry")
@click.option("--domain", required=True, help="Domain for the Tailscale cert")
@click.option("--command", help="Command to be run after updating keystore")
def main(
    keystore: str,
    storepass: str,
    keypass: Optional[str],
    alias: str,
    domain: str,
    command: Optional[str],
):
    if Path(keystore).exists():
        jks_keystore = jks.KeyStore.load(keystore, storepass)
        pk_entry = jks_keystore.private_keys.get(alias)
        if pk_entry is None:
            raise click.BadParameter(f"Keystore entry '{alias}' not found in keystore")

        if not pk_entry.is_decrypted():
            pk_entry.decrypt(keypass)

        certs_from_keystore = [
            x509.load_der_x509_certificate(cert_entry[1])
            for cert_entry in pk_entry.cert_chain
        ]
    else:
        jks_keystore = jks.KeyStore.new("jks", [])
        certs_from_keystore = []

    tailscale_client = TailscaleClient.create(domain)
    try:
        certs_from_tailscale = tailscale_client.get_certs()
    except httpx.HTTPStatusError as error:
        click.secho(
            f"Error from Tailscale: {error.response.text}",
            fg="red",
            err=True,
        )

        if error.response.status_code == 403 and os.geteuid() != 0:
            click.secho(
                "If not running as root, the user must have access "
                "to Tailscale's socket. See https://tailscale.com/kb"
                "/1190/caddy-certificates/#provide-non-root-users-with-"
                "access-to-fetch-certificate for more info.",
                fg="red",
                err=True,
            )
        sys.exit(1)

    if certs_from_keystore == certs_from_tailscale:
        click.echo("No update needed")
        return

    key = tailscale_client.get_key()

    raw_certs = [
        cert.public_bytes(serialization.Encoding.DER) for cert in certs_from_tailscale
    ]
    raw_key = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    pke = jks.PrivateKeyEntry.new(alias, raw_certs, raw_key)
    if keypass is not None:
        pke.encrypt(keypass)

    jks_keystore.entries[alias] = pke
    jks_keystore.save(keystore, storepass)

    if command is not None:
        os.system(command)


if __name__ == "__main__":
    main()
