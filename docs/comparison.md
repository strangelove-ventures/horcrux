|                    |      Num. Rounds     | Robust | Num. Signers | Parallel Secure |
|--------------------|:--------------------:|:------:|:------------:|:---------------:|
| **Stinson Strobl** |           4          |   Yes  |       t      |       Yes       |
| **Gennaro et al.** | 1 with preprocessing |   No   |       n      |        No       |
| **FROST**          | 1 with preprocessing |   No   |       t      |       Yes       |

| **Stinson Strobl** is the only implement Threshold Schemes in Horcrux. However, its worth important to note that the key generation in Horcrux is not the same as proposed in the paper. Instead its "classic" shamir secret sharing with a fully trusted dealer.  
