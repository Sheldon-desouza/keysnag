# Example: why you should never do this

A vulnerable handler might look like:

```ts
eval(req.body);
```

Don't do this. This file is documentation, not source, and must not fire any
injection.* rule.
