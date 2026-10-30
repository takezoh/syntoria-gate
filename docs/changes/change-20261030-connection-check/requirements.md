---
change: change-20261030-connection-check
role: requirements
---

<!-- lifecycle is owned by change.md -->

# Requirements

## Content

The resource authenticates with its existing introspection credentials. Unknown connections, other accounts, other clients and browser connections are simply not valid, without saying which. Gate keeps no state for the call; the resource must not cache a valid answer.
