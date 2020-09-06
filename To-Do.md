
# To-Do

- [ ] GET /authorize
  - [x] Validate AuthorizationRequest
    - [x] Create service methods
  - [ ] Check cookie `ZSC` and validate against DB
    - [x] Create service methods
  - [ ] Redirect to GET /authenticate (if no / invalid cookie)
  - [ ] Display consens form -> POST /authorize (if logged in)
  - [ ] Return errors in query (if an error occurs and `redirect_uri` is set)

- [ ] POST /authorize
  - [ ] Check cookie `ZSC` and validate against DB
  - [ ] Redirect to GET /authenticate (if no / invalid cookie)
  - [ ] Generate authorization code and persist AuthorizationResponse in DB
  - [ ] Return errors in query (if an error occurs and `redirect_uri` is set)
  - [ ] Redirect to `redirect_uri` (on success)

- [ ] GET /authenticate
  - [ ] Check cookie `ZSC` and validate against DB
  - [ ] Redirect to GET /logout (if cookie already present)
  - [ ] Display login provider form
  - [ ] Create session
  - [ ] Generate and persist `AuthenticationRequest {
                               authorizationRequest
                               sessionId
                               authenticationId
                               state
                             }` (should only be valid for 5 min)
- [ ] GET /authenticate/callback
  - [ ] Retrieve authorization code
  - [ ] Exchange code to token
  - [ ] Get user information
  - [ ] Map user information to sessionId
  - [ ] Redirect to GET /logout (on success, if no authorization request exists)
  - [ ] Redirect to GET /authorize (on success, if authorization request exists)
  - [ ] Redirect to GET /authenticate and display errors (on failure)


// http://localhost:8080/v1/authorize?client_id=solvent&response_type=code&redirect_uri=https://www.eldelto.net/solvent&scope=read&state=123

/* 	TODO
	 	Create FakeLoginProvider endpoint which calls our callback URL
		Create a callback handler which asserts if the state matches the fake provider method
		and sets a fake session cookie. Redirects back to /authorize.
		/authorize now finds a session cookie and lets you authorize the request.
		Create a authorization code in POST /authorize and store it in the repo.
		Redirect to the redirect_uri with the auth code.
*/