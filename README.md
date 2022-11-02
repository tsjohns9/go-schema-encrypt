# Build

`go build -o $OUTPUT_FILE_NAME main.go`

# Flags
```
-algorithm string
    The encryption algorithm (RSA-OAEP/PKCS)
-hash string
    The hash to use (SHA256)
-key string
    The file path to a public key
-schema string
    The file path to a json schema
-values string
    The file path to a json file that matches the provided json schema
```

# Run

`./$OUTPUT_FILE_NAME -key=public_key.pem -algorithm=RSA-OAEP -hash=SHA256 -schema=schema.json -values=values.json`
