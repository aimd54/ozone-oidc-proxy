# Clients

Anything that speaks the S3 API and understands AWS temporary credentials
works against the proxy. Web identity is an ordinary part of the SigV4
credential chain, so most clients need no plugin and no custom credential
provider.

The examples below use the compose lab's endpoints and users. Against your
own deployment, substitute your proxy address and your own accounts.

## Humans: `ozone-login` (device flow with auto-refresh)

```bash
make build
bin/ozone-login -issuer http://keycloak:8080/realms/ozone
# open the printed URL, sign in (alice / password123), leave it running
```

It writes `~/.ozone/token.jwt` (atomically, mode 0600), refreshes it at two
thirds of the token lifetime, and prints the exports every AWS SDK and CLI
needs to auto-exchange against the proxy:

```bash
export AWS_ROLE_ARN=arn:ozone:iam::dev:role/oidc
export AWS_WEB_IDENTITY_TOKEN_FILE=~/.ozone/token.jwt
export AWS_ENDPOINT_URL_STS=http://localhost:9000
export AWS_ENDPOINT_URL_S3=http://localhost:9000
aws s3 ls
```

Using `ozone-login` needs the OAuth 2.0 device authorization grant on a
public client at your provider.

## Humans: credential portal (browser)

```bash
make portal-up   # oauth2-proxy + portal at http://localhost:4180
```

Sign in as alice and copy the rendered credentials, either as shell exports
or as an `~/.aws/credentials` profile. Reload the page to mint a fresh set.

The portal needs a confidential client with a registered redirect URI.

## Scripts and CI: direct token exchange

```bash
TOKEN=$(curl -s http://localhost:8080/realms/ozone/protocol/openid-connect/token \
  -d grant_type=password -d client_id=ozone-s3 \
  -d username=alice -d password=password123 | jq -r .access_token)  # password grant: lab only

aws sts assume-role-with-web-identity \
  --endpoint-url http://localhost:9000 \
  --role-arn arn:ozone:iam::dev:role/oidc \
  --role-session-name alice-dev \
  --web-identity-token "$TOKEN"
# export the returned AccessKeyId / SecretAccessKey / SessionToken, then:
aws s3 mb s3://demo --endpoint-url http://localhost:9000
aws s3 cp report.csv s3://demo/ --endpoint-url http://localhost:9000
```

The temporary credentials' TTL is capped by the JWT's own `exp`, so your
provider's access-token lifespan sets the ceiling. The lab client uses one
hour. `ozone-login` papers over the limit by refreshing.

## Bearer tokens: curl, browsers, custom clients

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/demo/report.csv
curl -X PUT -H "Authorization: Bearer $TOKEN" --data-binary @report.csv \
     http://localhost:9000/demo/report.csv
```

## Presigned URLs

Presigned URLs must be signed with SigV4. The proxy verifies SigV4 only and
answers a SigV2 URL with `InvalidRequest` and the guidance to sign with
`AWS4-HMAC-SHA256`.

**aws CLI v1 signs presigned URLs with SigV2 by default**, so `aws s3
presign` produces a link this proxy rejects. aws CLI v2 uses SigV4 and needs
no configuration. Check which one you have, since `pip install awscli` and
`uv run --with awscli` both give you v1:

```bash
aws --version        # aws-cli/1.x signs SigV2; aws-cli/2.x signs SigV4
```

On v1, pin the signature version in `~/.aws/config`. There is no environment
variable for this setting, so the config file is the only way:

```ini
[default]
region = us-east-1
s3 =
    signature_version = s3v4
```

Then:

```bash
URL=$(aws s3 presign s3://demo/report.csv --expires-in 3600 \
    --endpoint-url http://localhost:9000)
curl "$URL"        # no credentials needed until the URL expires
```

A SigV4 URL carries `X-Amz-Algorithm` and `X-Amz-Signature`. A SigV2 one
carries `AWSAccessKeyId` and `Signature`, which is the quickest way to tell
which you got.

The link is bound to the temporary credentials that minted it, so it stops
working when they expire, whichever comes first: `X-Amz-Expires` or the
credential TTL.

## boto3, mc, s3a

All three run against the live stack in the acceptance suite. boto3 mints
its own credentials from environment variables alone, mc's 8 MiB
`aws-chunked` streaming upload is verified on the wire, and s3a reads that
same object back byte-identical.

boto3 picks up the same environment variables as the aws CLI, including the
web-identity auto-exchange. For mc and s3a, pass the minted credentials
explicitly:

```bash
# minio mc: the session token goes inside the alias URL
export MC_HOST_ozone="http://$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY:$AWS_SESSION_TOKEN@localhost:9000"
mc ls ozone/demo

# Hadoop s3a (3.4+ / AWS SDK v2)
hadoop fs \
  -D fs.s3a.endpoint=http://localhost:9000 -D fs.s3a.endpoint.region=us-east-1 \
  -D fs.s3a.path.style.access=true \
  -D fs.s3a.aws.credentials.provider=org.apache.hadoop.fs.s3a.TemporaryAWSCredentialsProvider \
  -D fs.s3a.access.key=$AWS_ACCESS_KEY_ID -D fs.s3a.secret.key=$AWS_SECRET_ACCESS_KEY \
  -D fs.s3a.session.token=$AWS_SESSION_TOKEN \
  -ls s3a://demo/
```

Streaming uploads (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, aws-chunked) pass
through the proxy verified. mc and the AWS SDK v2 use them by default on
plain HTTP.

The fuller compatibility table, with the credential-lifecycle caveats per
client, is in [architecture.md](architecture.md).

## Granting access

Buckets created through the proxy belong to the OIDC user who created them.
Cross-user grants use plain Ozone ACLs:

```bash
docker compose -f examples/compose/docker-compose.yml exec ozone-om \
  ozone sh bucket addacl -a user:bob:rl /s3v/demo            # bob may list and read
  # 'user:bob:rwl[DEFAULT]' additionally inherits to new keys
```
