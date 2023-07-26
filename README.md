# Oathent

## Description

[Oathent](https://github.com/Oathent) is an API-based authentication system.

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


# development
$ yarn run start

# watch mode
$ yarn run start:dev

# production mode
$ yarn run start:prod
```

## Configuration

### Oathent server
Create a `.env` file and set configurable values within the file. An example configuration can be found in `example.env`

### Database
Create a `db.env` file and set configurable values within the file. An example configuration can be found in `db.example.env`

### Custom scopes
Create a `custom-scopes.json` file and create new custom scopes within the file. You may not overwrite default scopes from Oathent and all scope values must be unique powers of 2.

#### Example
```json
{
    "custom:first": 512,
    "custom:second": 1024,
}
```
Note: Custom scopes cannot have values under 256 to avoid the possibility of a future update of Oathent interfering with existing custom scopes.