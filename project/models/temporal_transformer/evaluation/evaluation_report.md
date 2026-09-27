# P1.8 - P1.10 Evaluation Report

## P1.8 Proper Baseline Comparison
| Model               | Precision | Recall | F1 | FPR |
| ------------------- | --------: | -----: | -: | --: |
| Logistic Regression | N/A | N/A | N/A | N/A |
| Transformer         | 0.9721 | 0.9622 | 0.9671 | 0.0278 |

## P1.9 Multi-horizon Evaluation
| Horizon | Precision | Recall | F1 | FPR |
| ------- | --------: | -----: | -: | --: |
| now | 0.9156 | 0.9824 | 0.9478 | 0.0908 |
| future_5s | 0.4328 | 0.7855 | 0.5581 | 0.9750 |
| future_10s | 0.4946 | 0.9011 | 0.6386 | 0.8669 |
| future_15s | 0.5117 | 0.9872 | 0.6740 | 0.8802 |
| future_30s | 0.4224 | 0.7676 | 0.5449 | 0.9673 |
| future_60s | 0.4804 | 0.9081 | 0.6284 | 0.8905 |

## P1.10 Early-warning Evaluation
```text
Mean early warning time: -5.00 steps
Median early warning time: -5.00 steps
Minimum warning time: -5.00 steps
Maximum warning time: -5.00 steps
% attacks warned before onset: 0.0%
% attacks with no warning: 0.0%
```
