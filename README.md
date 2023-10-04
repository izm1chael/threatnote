![img](https://i.imgur.com/xqc8bGL.png)

## Getting Started
Check out the docs at https://docs.threatnote.io/ to get started!

## Quick Start
First you'll want to clone the threatnote.io repo
```
$ git clone https://github.com/izm1chael/threatnote.git
$ cd threatnote
$ docker-compose up
```
This will launch the following:

- Flask app running threatnote.io listening on port 5000 (access http://localhost:5000 to login)
- Redis server to manage Redis workers
- A Redis worker named enricher to manage the enrichment jobs

To stop threatnote.io, just run:
`$ docker-compose down`

To login, use admin@threatnote.io and admin as your credentials

For a general overview of the product, check out https://threatnote.io
