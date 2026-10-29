---
change: change-20261028-change-confirmation
role: requirements
---

<!-- lifecycle is owned by change.md -->

# Requirements

## Content

The owner decided that authorization does not depend on which AI makes a request; it depends on whether the person approved. Connection approval lets an AI use a resource. A user decision or a governance operation in a resource needs the person's approval of that exact change. The resource-side contract is the change confirmation design in the Lore repository (`docs/design/change-confirmation.md`, requirements G-1 to G-9).

- **G-1** When a resource creates a confirmation, Gate shall store it only if the subject is the configured account and the connection is an active approved OAuth connection of that subject.
- **G-2** Gate shall return a confirmation's state only to the resource that created it.
- **G-3** When `GET /confirm` is requested without an identity session, Gate shall start sign-in on request and return to that confirmation.
- **G-4** If the signed-in identity is not the confirmation's subject, Gate shall refuse to display or decide it.
- **G-5** When a decision is posted, Gate shall accept it only with the issuer Origin, the identity CSRF value, exactly the expected fields, a pending record and an active requesting connection.
- **G-6** When an approved confirmation is consumed with matching reference and hash while its connection is active, Gate shall mark it used in the same transaction and report `consumed` exactly once.
- **G-7** While the requesting connection is revoked or its grant has expired, Gate shall treat its confirmations as expired.
- **G-8** Gate shall delete a confirmation's summary when it is denied, consumed or cancelled.
- **G-9** If storage or validation fails, Gate shall create, approve or consume nothing.

Owner decisions on 2026-10-28: a confirmation has no timer and no pending limit, approval needs the Gate sign-in only, and Gate never truncates a summary. The pages follow the owner-requested design for the approval flow and the connections list.
