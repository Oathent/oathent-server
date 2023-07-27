# Oathent

## Description

[Oathent](https://github.com/Oathent) is a REST API authentication system.

It supports modern authentication flows and custom auth scopes.

## Requirements
- Node.js
- Docker

## Installation

```bash
# install dependencies
$ yarn install

# migrate database (database must be running to work)
$ yarn prisma migrate deploy
```

## Running the app

```bash
# start database
$ docker compose up
```
```bash
# development
$ yarn run start

# watch mode
$ yarn run start:dev

# production mode
$ yarn run start:prod
```

## Configuration

### Oathent server
Create a `.env` file and set configurable values within the file. An example configuration can be found in `example.env`.

If you intend to use HTTPS (recommended), put your SSL key pair at the paths `secrets/private-key.pem` and `secrets/public-certificate.pem`.

If you instead intend to use HTTP, set `USE_HTTP` in `.env` to `"yes"`. **This is not recommended as it introduces the risk of a [man-in-the-middle attack](https://wikipedia.org/wiki/Man-in-the-middle_attack).**

### Database
Create a `db.env` file and set configurable values within the file. An example configuration can be found in `db.example.env`.

### Custom scopes
Create a `custom-scopes.json` file and create new custom scopes within the file. Custom scopes can have any name, however, you may not overwrite default scopes from Oathent and all scope values must be unique powers of 2.

#### Example
```json
{
    "custom:first": 256,
    "custom:second": 512,
}
```
Note: Custom scopes cannot have values under 256 to avoid the possibility of a future update of Oathent interfering with existing custom scopes.


## Docs

If not disabled in `.env`, Swagger docs for the API are hosted at the path `/docs` on the auth server.

The docs show all the endpoints available with a description of all request and response payloads.

Custom CSS can be applied to the docs by creating and populating a `swagger.custom.css` file.

----

Oathent is licensed under the MIT license.
