# `query_llm` Gate Design

Every quarantined model call flows through `query_llm`:

```text
request
  -> deterministic preflight rules
  -> if blocked, do not call model
  -> deterministic quarantined model stub
  -> deterministic postflight rules over output trace
  -> optional FIDES/IFC layer
  -> structured QueryResult
```

Default policy:

- deterministic preflight block prevents the model call;
- deterministic postflight block prevents downstream action;
- FIDES/IFC unsafe blocks;
- disabled FIDES reports `disabled` and does not block;
- real provider calls are not part of the MVP.

The key research point is separation of duties: rules and FIDES make policy decisions over structured traces; enforcement code only executes the resulting allow/block decision.
