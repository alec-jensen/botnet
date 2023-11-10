# botnet

This is a simple botnet written in python. It is not complete, but it is functional. It is meant to be used for educational purposes only.

## Usage

### Server

The server controls all of the agents. You can interact with the server through the API. You can view the API documentation by starting the server and navigating to `http://localhost:8000/docs`.

Make a new MongoDB database.

Make a config file at the server root called `config.json`. Populate it like so:

```json
{
    "dbstring": "your database connection string"
}
```

Use `uvicorn main:app` to start the server.

### Agent

To create an agent, you must first register it through the API. Once that is done, fill in all the necessary details in the agent file.

### Sending Commands

To send commands to the agents, you need to register a user through the API. Once that is done, go into MongoDB, find the user in the `users` collection, and edit the `is_allowed` field to `true`. Then, you can send commands to the agents through the API.

*This readme is purposely vague to prevent script kiddies from using this for malicious purposes. If you are using this for educational purposes, you should be able to figure out how to use it.*