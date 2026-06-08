# natcf

Cloudflare publisher for `github.com/csbxd/natnet`.

`Client` implements `natnet.Syncer`. It updates the Cloudflare origin rule port
and overwrites the configured DNS record when the public address changes.

```go
cf := natcf.New(natcf.Config{
	Zone:      "...",
	Record:    "...",
	RulesetID: "...",
	RuleID:    "...",
	APIKey:    os.Getenv("CLOUDFLARE_API_TOKEN"),
	Domain:    "*.example.com",
})

r, err := natnet.Start(ctx, natnet.Config{
	LocalAddr: &net.TCPAddr{Port: 26656},
	Syncer:    cf,
})
```

The client uses Cloudflare's rule update endpoint
`PATCH /zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}` and DNS overwrite
endpoint `PUT /zones/{zone_id}/dns_records/{dns_record_id}`.
