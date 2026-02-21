# Sequence Diagrams

## Login + 2FA + Key Session
```mermaid
sequenceDiagram
    participant U as User
    participant W as Web App
    participant A as Auth + Profile
    U->>W: POST username/password(+otp)
    W->>A: authenticate(username,password)
    A-->>W: user/profile
    W->>A: verify TOTP (if enabled)
    A-->>W: valid/invalid
    W->>W: derive master key; store session key marker
    W-->>U: dashboard or setup-2FA
```

## Upload -> Encrypt -> Index
```mermaid
sequenceDiagram
    participant U as User
    participant W as Web App
    participant C as Crypto Layer
    participant D as DB
    U->>W: Upload file
    W->>C: encrypt_file_data(file, key)
    C-->>W: encrypted blob + file_id
    W->>C: build encrypted token index
    C-->>W: token entries
    W->>D: store encrypted blob + token index
    W-->>U: upload success + metrics
```

## Search -> Candidate -> Verify
```mermaid
sequenceDiagram
    participant U as User
    participant W as Web App
    participant D as DB
    participant C as Crypto Layer
    U->>W: search query + mode
    W->>C: generate encrypted search tokens
    W->>D: token lookups (+decoy lookups)
    D-->>W: candidate IDs + scores
    W->>C: decrypt candidates for preview/regex verify
    C-->>W: verified matches
    W-->>U: ranked results
```
