# Dodo
A dead simple document store!

## Why Dodo?
Because it's dead. Simple that is. **Dodo** is designed to be simple in concept, simple to use, and simple to master.

## What is it?
**Dodo** receives documents via a JSON HTTP request, stores the documents as a JSON file, and returns documents as a JSON response.

**Dodo** is open-source. It's built with Go (Golang) and also uses Docker to make development and installation easy.

## Running Dodo
### Docker
If you have the source checked out, you can build the image locally:

```docker build -t dodo .```

This will produce an image with the tag _dodo_.

You'll also want to create a _volume_:

```docker volume create dodo_data```

We can now run our container:

```docker run -d -p 6060:6060 -v dodo_data:/store dodo```

Note that we're binding port **6060** on the host to **6060** on the container. **Dodo** exposes port 6060 by default. You can use any host port you like, but this setup will assume you're using port 6060.

### Golang
The simplest way to run **Dodo** is to issue:

```go run main.go```

### Docker Hub
**Dodo** is available on Docker Hub. You can pull it by issuing:

```docker pull danielwoodsdeveloper/dodo```

You can then run it:

```docker run -d -p 6060:6060 -v dodo_data:/store danielwoodsdeveloper/dodo```

## API

| Function                    | URL            | Method | Request                              | Normal Response                  |
| --------------------------- | -------------- | :----: | ------------------------------------ | -------------------------------- |
| Store new document          | /store         |  PUT   | JSON you wish to store.              | ```{"id": ID}``` and HTTP 200.   |
| Get stored document         | /document/{id} |  GET   | Nil.                                 | Stored JSON and HTTP 200.        |
| Modify stored document      | /document/{id} |  POST  | New JSON document.                   | HTTP 200.                        |
| Delete stored document      | /document/{id} | DELETE | Nil.                                 | HTTP 200.                        |
| Get all stored documents    | /all           |  GET   | Nil.                                 | All stored JSON and HTTP 200.    |
| Delete all stored documents | /all           | DELETE | Nil.                                 | HTTP 200.                        |
| Generate JWT.               | /authenticate  |  POST  | ```{"username": u, "password": p}``` | ```{"jwt": JWT}``` and HTTP 200. |

## Authentication and Authorisation

**Dodo** uses JWT to authenticate access to the APIs. Before using the APIs, you must call ```/authenticate``` and pass in the system username and password. The system username is specified via an environment variable *SYSTEM_USERNAME* and the system password with the variable *SYSTEM_PASSWORD*. The username and password in the ```/authenticate``` request must match these environment variables.

Passwords passed over the wire unencrypted is never a good idea, so passwords sent in ```/authenticate``` request should be hashed. **Dodo** expects as SHA256 hashed password. It also expects it to have been salted with a salt known **Dodo**. This is salt is passed in as an environment variable so you're free to choose it; the environment variable is *PASSWORD_SALT*. Keep this secure.

Salting works to prevent rainbow table attacks. The general idea is that the plaintext password is suffixed with the salt, and then this entire string is hashed. For example, if the password were ```password``` and the salt were ```12345```, ```password12345``` would be run through the hashing algorithm. This improves the security of passwords, as now attackers need to know both the password and the salt (or at a minimum a salt to generate a rainbow table for a brute force attack).

You can also specify the JWT secret used during singing with the *JWT_SECRET* environment variable.

The default values are:
- **Username:** admin
- **Password:** VKIL3G6UZUWLM09RJ0WA
- **Salt:** 5FMI7M57NZ3W083RVQVO
- **JWT Secret:** ASVMTBVVKGKV6RZVEL1W

If you wish to use **Dodo** without mandatory JWT authentication, run **Dodo** with the environment variable *JWT_REQUIRED* set to *FALSE*. If this environment variable is not set accordingly, authentication will be mandatory.