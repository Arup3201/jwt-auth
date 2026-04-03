# Backend

## Setup

Generate RSA private and public key pair:

Following will generate `private.key`.

```sh
openssl genrsa -out private.key 2048
```

Following will create `public.key` from the `private.key`.

```sh
opensll rsa -in private.key -pubout -out public.key
```
