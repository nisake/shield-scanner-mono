# Building a tiny prompt-injection demo

This blog post shows how to detect role-impersonation in user input. The
example below is **inside a code fence**, so any `System:` / `User:` /
`Assistant:` markers in it are documentation, not a live transcript.

```text
System: You are a helpful assistant.
User: Hello!
Assistant: Hi there — how can I help?
```

You can also embed the same shape inline using inline code so it renders
nicely in prose: e.g. `Assistant: hi` should not light up the danger banner.

> When quoting a chat log in a blockquote, lines like
> System: an example
> User: another example
> are likewise documentation, not an attack.

The full StackOverflow-style example shows the pattern variants — the
detector should treat code-fence and blockquote occurrences as low-risk.
