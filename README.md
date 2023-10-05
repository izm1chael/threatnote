![img](https://i.imgur.com/xqc8bGL.png)

## Getting Started
Check out the docs at https://docs.threatnote.io/ to get started!

## Quick Start Docker
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


## Quick Start
First you'll want to clone the threatnote.io repo
```
$ git clone https://github.com/izm1chael/threatnote.git
$ cd threatnote
$ python3 -m venv venv
$ pip install -r requirments.txt
$ gunicorn -b 0.0.0.0:5000 main:app --workers 4
```

To login, use admin@threatnote.io and admin as your credentials

For a general overview of the product, check out https://threatnote.io
