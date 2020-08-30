
# To-Do

- [ ] GET /authorize
  - [ ] Check cookie `ZSC` and validate against DB
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

