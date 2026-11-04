# Detections

One file per detection, matching a simulation in [`../simulations/`](../simulations/).

```markdown
# NN: <Detection name>

- **ATT&CK technique:** <ID>
- **Rule type:** Built-in Wazuh rule <ID> / Custom rule <ID>

## Logic
What the rule looks for and why.

## Rule
(XML for custom rules)

## Testing
How it was triggered, and the alert it produced.

## False positives and tuning
What normal activity could trigger it, and how it was tuned.
```
