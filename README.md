# speech wtf

Server for messenger speech wtf

### Instructions to build

1. Clone this project
2. Install progress
3. Create users database in progress
4. Create redis cache database
5. Setup databases settings in database.go and redis.go

## Authorization

Now we use jvt authentication, this will definitely change in the future, but for now it’s like this

### Registration

url: ```/registration```

body:

```json
{
	"username": "username",
	"password": "12345678",
	"email": "user@email.com"
}
```

### Login

url: ```/login```

body:

```json
{
	"password": "12345678",
	"email": "user@email.com"
}
```
