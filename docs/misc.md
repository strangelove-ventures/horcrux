# Misc

|                    |      Num. Rounds     | Robust | Num. Signers | Parallel Secure |
|--------------------|:--------------------:|:------:|:------------:|:---------------:|
| **Stinson Strobl [^1]** |           4          |   Yes  |       t      |       Yes       |
| **Gennaro et al. [^2]** | 1 with preprocessing |   No   |       n      |        No       |
| **FROST** [^3]          | 1 with preprocessing |   No   |       t      |       Yes       |
| **ROAST** [^TBD]          | TBD |   TBD   |       TBD      |       TBD       |
**Stinson Strobl** threshold signature scheme is the **only** implemented <u>Threshold Scheme</u> in Horcrux so far. However, its important to note that the key generation in Horcrux is not fully the same as proposed in the paper. Instead of using Pedersen´s Verifiable Secret Sharing (PVSS) Horxruc uses "classic" shamir secret sharing with a fully trusted dealer.


### Overview

#### Stinson and Strobl
**Stinson and Strobl**[^1] is a threshold signature scheme producing Schnorr signatures. It uses a modification of Pedersen’s DKG presented by Gennaro et al.[^4] to generate both the <u>*secret key s*</u> during key generation as well as the <u>*random nonce k*</u> for each signing operation. 

This construction requires at minimum <u>four rounds</u> for each signing operation (assuming no participant misbehaves): 
- three rounds to perform the DKG to obtain k (the random nonce), 
- and one round to distribute signature shares and compute the group signature. 

Each round requires participants to send values to every other participant.


[^1]: Stinson, D.R., Strobl, R. (2001). Provably Secure Distributed Schnorr Signatures and a (t, n) Threshold Scheme for Implicit Certificates. In: Varadharajan, V., Mu, Y. (eds) Information Security and Privacy. ACISP 2001. Lecture Notes in Computer Science, vol 2119. Springer, Berlin, Heidelberg. [](https://doi.org/10.1007/3-540-47719-5_33)https://doi.org/10.1007/3-540-47719-5_33
[^2]: Gennaro, R., Goldfeder, S. (2020). One Round Threshold ECDSA with Identifiable Abort. In: Cryptology ePrint Archive, Paper 2020/540. [](https://eprint.iacr.org/2020/540)https://eprint.iacr.org/2020/540
[^3]: Komlo, C., Goldberg, I. (2021). FROST: Flexible Round-Optimized Schnorr Threshold Signatures. In: Dunkelman, O., Jacobson, Jr., M.J., O'Flynn, C. (eds) Selected Areas in Cryptography. SAC 2020. Lecture Notes in Computer Science(), vol 12804. Springer, Cham. [](https://eprint.iacr.org/2020/852.pdf)https://eprint.iacr.org/2020/852.pdf
[^4]: Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin. Secure Distributed Key Generation for Discrete-Log Based Cryptosystems. Journal of Cryptology, 20:51–83, 2007.

### Glossary - WORK IN PROGRESS

- In cryptography, a **nonce** (number once) is an arbitrary number that can be used just once in a cryptographic communication.

- A cryptographic key is called **ephemeral** if it is generated for each execution of a key establishment process. 

- **Threshold signatures** allow for splitting a private key into n secret shares. To sign a message, at least some threshold of the shareholders need to coordinate and provide their individual signatures using their share. These individual signatures combine to form a single valid signature.

- **Robust schemes** ensure that so long as t participants correctly follow the protocol, the protocol is guaranteed to complete successfully, even if a subset of participants (at most n − t) contribute malformed shares. 
