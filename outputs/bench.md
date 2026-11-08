Environment: Python 3.12.3, cryptography 50.0.2, Linux 6.8.0-146-generic, CPU cores: 2, repeat=3

| Size | Mode | Enc avg (s) | Dec avg (s) | Enc MB/s | Dec MB/s | Enc CPU (s) | Dec CPU (s) | Enc peak RAM (MB) | Dec peak RAM (MB) | Overhead (B) | OK |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| 1MB | CBC-HMAC | 0.010 | 0.013 | 102 | 75 | 0.010 | 0.013 | 3.0 | 4.0 | 187 | OK |
| 1MB | GCM | 0.005 | 0.008 | 191 | 125 | 0.005 | 0.008 | 2.0 | 3.0 | 109 | OK |
| 10MB | CBC-HMAC | 0.074 | 0.916 | 134 | 11 | 0.063 | 0.915 | 3.0 | 40.0 | 187 | OK |
| 10MB | GCM | 0.032 | 0.057 | 316 | 176 | 0.031 | 0.056 | 2.0 | 30.0 | 109 | OK |
| 100MB | CBC-HMAC | 0.630 | 4.018 | 159 | 25 | 0.487 | 3.919 | 3.0 | 400.0 | 187 | OK |
| 100MB | GCM | 0.320 | 0.626 | 312 | 160 | 0.287 | 0.533 | 2.0 | 300.0 | 109 | OK |
