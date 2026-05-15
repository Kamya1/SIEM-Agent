# Evaluation report

- Source: `dataset:lanl_auth_sample.csv`

## Summary by mode

| Mode | Retention | Consistency | Personalization | Aggregate |
|------|-----------|-------------|-----------------|-----------|
| no_memory | 0.183 | 0.665 | 0.344 | 0.376 |
| short_term | 0.198 | 0.804 | 0.188 | 0.377 |
| long_term | 0.138 | 0.906 | 0.188 | 0.383 |
| hybrid | 0.131 | 0.911 | 0.156 | 0.373 |

## Per scenario

| Scenario | Mode | R | C | P | Agg | Latency ms |
|----------|------|---|---|---|-----|------------|
| lanl-failed-logins-001 | no_memory | 0.46 | 0.41 | 0.75 | 0.53 | 1875 |
| lanl-failed-logins-001 | short_term | 0.50 | 0.53 | 0.25 | 0.43 | 1977 |
| lanl-failed-logins-001 | long_term | 0.39 | 0.82 | 0.50 | 0.55 | 2047 |
| lanl-failed-logins-001 | hybrid | 0.50 | 0.80 | 0.50 | 0.59 | 3878 |
| lanl-same-source-repeated | no_memory | 0.43 | 0.39 | 0.75 | 0.52 | 3307 |
| lanl-same-source-repeated | short_term | 0.55 | 0.95 | 0.75 | 0.73 | 6646 |
| lanl-same-source-repeated | long_term | 0.62 | 0.86 | 0.75 | 0.73 | 4648 |
| lanl-same-source-repeated | hybrid | 0.55 | 0.87 | 0.75 | 0.70 | 4802 |
| lanl-suspicious-sequence | no_memory | 0.51 | 0.48 | 1.00 | 0.65 | 3150 |
| lanl-suspicious-sequence | short_term | 0.54 | 0.32 | 0.50 | 0.46 | 6492 |
| lanl-suspicious-sequence | long_term | 0.10 | 0.94 | 0.25 | 0.40 | 1566 |
| lanl-suspicious-sequence | hybrid | 0.00 | 0.94 | 0.00 | 0.28 | 649 |
| lanl-privilege-escalation | no_memory | 0.06 | 0.91 | 0.25 | 0.37 | 29537 |
| lanl-privilege-escalation | short_term | 0.00 | 0.91 | 0.00 | 0.27 | 767 |
| lanl-privilege-escalation | long_term | 0.00 | 0.91 | 0.00 | 0.27 | 1235 |
| lanl-privilege-escalation | hybrid | 0.00 | 0.94 | 0.00 | 0.28 | 608 |
| lanl-lateral-movement | no_memory | 0.00 | 0.94 | 0.00 | 0.28 | 826 |
| lanl-lateral-movement | short_term | 0.00 | 0.91 | 0.00 | 0.27 | 516 |
| lanl-lateral-movement | long_term | 0.00 | 0.91 | 0.00 | 0.27 | 748 |
| lanl-lateral-movement | hybrid | 0.00 | 0.94 | 0.00 | 0.28 | 1114 |
| lanl-after-hours | no_memory | 0.00 | 0.94 | 0.00 | 0.28 | 578 |
| lanl-after-hours | short_term | 0.00 | 0.94 | 0.00 | 0.28 | 530 |
| lanl-after-hours | long_term | 0.00 | 0.91 | 0.00 | 0.27 | 864 |
| lanl-after-hours | hybrid | 0.00 | 0.91 | 0.00 | 0.27 | 1277 |
| lanl-credential-stuffing | no_memory | 0.00 | 0.33 | 0.00 | 0.10 | 641 |
| lanl-credential-stuffing | short_term | 0.00 | 0.94 | 0.00 | 0.28 | 487 |
| lanl-credential-stuffing | long_term | 0.00 | 0.94 | 0.00 | 0.28 | 596 |
| lanl-credential-stuffing | hybrid | 0.00 | 0.94 | 0.00 | 0.28 | 500 |
| cross-session-recall-001 | no_memory | 0.00 | 0.91 | 0.00 | 0.27 | 473 |
| cross-session-recall-001 | short_term | 0.00 | 0.91 | 0.00 | 0.27 | 750 |
| cross-session-recall-001 | long_term | 0.00 | 0.94 | 0.00 | 0.28 | 596 |
| cross-session-recall-001 | hybrid | 0.00 | 0.94 | 0.00 | 0.28 | 488 |