#ifndef __ELECTIONGUARD_CHAUM_PEDERSEN_H_INCLUDED__
#define __ELECTIONGUARD_CHAUM_PEDERSEN_H_INCLUDED__

#include "elgamal.h"
#include "export.h"
#include "group.h"
#include "status.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DisjunctiveChaumPedersenProof

struct eg_disjunctive_chaum_pedersen_proof_s;

/**
* The Disjunctive Chaum Pederson proof is a Non-Interactive Zero-Knowledge Proof
* that represents the proof of ballot correctness (that a value is either zero or one).
* This proof demonstrates that an ElGamal encryption pair (𝛼,𝛽) is an encryption of zero or one
* (given knowledge of encryption nonce R).
*
* This object should not be constructed directly.  Use `eg_disjunctive_chaum_pedersen_proof_make`
*
* see: https://www.electionguard.vote/spec/0.95.0/5_Ballot_encryption/#outline-for-proofs-of-ballot-correctness
*/
typedef struct eg_disjunctive_chaum_pedersen_proof_s eg_disjunctive_chaum_pedersen_proof_t;

// No constructor provided.  Use `eg_disjunctive_chaum_pedersen_proof_make`

EG_API eg_electionguard_status_t
eg_disjunctive_chaum_pedersen_proof_free(eg_disjunctive_chaum_pedersen_proof_t *handle);

/**
 * a0 in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModP zero pad.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_disjunctive_chaum_pedersen_proof_get_zero_pad(
  eg_disjunctive_chaum_pedersen_proof_t *handle, eg_element_mod_p_t **out_element_ref);

/**
 * b0 in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModP zero data.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_disjunctive_chaum_pedersen_proof_get_zero_data(
  eg_disjunctive_chaum_pedersen_proof_t *handle, eg_element_mod_p_t **out_element_ref);

/**
 * a1 in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModP one pad.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_disjunctive_chaum_pedersen_proof_get_one_pad(
  eg_disjunctive_chaum_pedersen_proof_t *handle, eg_element_mod_p_t **out_element_ref);

/**
 * b1 in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModP one data.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_disjunctive_chaum_pedersen_proof_get_one_data(
  eg_disjunctive_chaum_pedersen_proof_t *handle, eg_element_mod_p_t **out_element_ref);

/**
 * c0 in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModQ zero challenge.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_disjunctive_chaum_pedersen_proof_get_zero_challenge(
  eg_disjunctive_chaum_pedersen_proof_t *handle, eg_element_mod_q_t **out_element_ref);

/**
 * c1 in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModQ one challenge.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_disjunctive_chaum_pedersen_proof_get_one_challenge(
  eg_disjunctive_chaum_pedersen_proof_t *handle, eg_element_mod_q_t **out_element_ref);

/**
 * c in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModQ challenge.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_disjunctive_chaum_pedersen_proof_get_challenge(
  eg_disjunctive_chaum_pedersen_proof_t *handle, eg_element_mod_q_t **out_element_ref);

/**
 * v0 in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModQ zero response.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_disjunctive_chaum_pedersen_proof_get_zero_response(
  eg_disjunctive_chaum_pedersen_proof_t *handle, eg_element_mod_q_t **out_element_ref);

/**
 * v1 in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModQ one response.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_disjunctive_chaum_pedersen_proof_get_one_response(
  eg_disjunctive_chaum_pedersen_proof_t *handle, eg_element_mod_q_t **out_element_ref);

/**
 * make function for a `DisjunctiveChaumPedersenProof`
 *
 * This overload does not accept a seed value and calculates
 * proofs independent of the original encryption. (faster performance)
 * @param[in] in_message The ciphertext message
 * @param[in] in_r The nonce used creating the ElGamal ciphertext
 * @param[in] in_k The public key of the election
 * @param[in] in_q A value used when generating the challenge,
 *                 usually the election extended base hash (𝑄')
 * @param[in] in_plaintext Zero or one
 * @param[out] out_handle A handle to an `eg_disjunctive_chaum_pedersen_proof_t`. 
 *                        Caller is responsible for lifecycle.
 */
EG_API eg_electionguard_status_t eg_disjunctive_chaum_pedersen_proof_make(
  eg_elgamal_ciphertext_t *in_message, eg_element_mod_q_t *in_r, eg_element_mod_p_t *in_k,
  eg_element_mod_q_t *in_q, uint64_t in_plaintext,
  eg_disjunctive_chaum_pedersen_proof_t **out_handle);

/**
 * make function for a `DisjunctiveChaumPedersenProof`
 *
 * This overload accepts a seed value and calculates
 * proofs deterministically based on the seed. (slower, but reproduceable proofs)
 * @param[in] in_message The ciphertext message
 * @param[in] in_r The nonce used creating the ElGamal ciphertext
 * @param[in] in_k The public key of the election
 * @param[in] in_q A value used when generating the challenge,
 *                 usually the election extended base hash (𝑄')
 * @param[in] in_seed Used to generate other random values here
 * @param[in] in_plaintext Zero or one
 * @param[out] out_handle A handle to an `eg_disjunctive_chaum_pedersen_proof_t`. 
 *                        Caller is responsible for lifecycle.
 */
EG_API eg_electionguard_status_t eg_disjunctive_chaum_pedersen_proof_make_deterministic(
  eg_elgamal_ciphertext_t *in_message, eg_element_mod_q_t *in_r, eg_element_mod_p_t *in_k,
  eg_element_mod_q_t *in_q, eg_element_mod_q_t *in_seed, uint64_t in_plaintext,
  eg_disjunctive_chaum_pedersen_proof_t **out_handle);

/**
 * Validates a "disjunctive" Chaum-Pedersen (zero or one) proof.
 *
 * @param[in] in_message The ciphertext message
 * @param[in] in_k The public key of the election
 * @param[in] in_q The extended base hash of the election
 */
EG_API bool
eg_disjunctive_chaum_pedersen_proof_is_valid(eg_disjunctive_chaum_pedersen_proof_t *handle,
                                             eg_elgamal_ciphertext_t *in_message,
                                             eg_element_mod_p_t *in_k, eg_element_mod_q_t *in_q);

#endif

#ifndef RangedChaumPedersenProof

/**
* The Ranged Chaum Pederson proof is a Non-Interactive Zero-Knowledge Proof
* that represents the proof of ballot correctness (that a value is in the range [0,n]).
* This proof demonstrates that an ElGamal encryption pair (𝛼,𝛽) is a number between 0 and n, inclusive
* (given knowledge of encryption nonce R).
*
* This object should not be constructed directly.  Use `eg_ranged_chaum_pedersen_proof_make`
*/
struct eg_ranged_chaum_pedersen_proof_s;

typedef struct eg_ranged_chaum_pedersen_proof_s eg_ranged_chaum_pedersen_proof_t;

// No constructor provided.  Use `eg_disjunctive_chaum_pedersen_proof_make`

/**
 * @brief get the proof's range limit
 * 
 * @param handle A handle to a `eg_ranged_chaum_pedersen_proof_t` opaque instance
 * @param out_element_ref range limit
 **/
EG_API eg_electionguard_status_t eg_ranged_chaum_pedersen_proof_get_range_limit(
  eg_ranged_chaum_pedersen_proof_t *handle, uint64_t *out_element_ref);

/**
 * @brief get the proof's challenge
 * 
 * @param handle A handle to a `eg_ranged_chaum_pedersen_proof_t` opaque instance
 * @param out_element_ref challenge
 */
EG_API eg_electionguard_status_t eg_ranged_chaum_pedersen_proof_get_challenge(
  eg_ranged_chaum_pedersen_proof_t *handle, eg_element_mod_q_t **out_element_ref);

EG_API eg_electionguard_status_t
eg_ranged_chaum_pedersen_proof_free(eg_ranged_chaum_pedersen_proof_t *handle);

/**
 * make function for a `RangedChaumPedersenProof`
 *
 * This overload does not accept a seed value and calculates
 * proofs independent of the original encryption. (faster performance)
 * @param[in] in_message The ciphertext message
 * @param[in] in_r The nonce used creating the ElGamal ciphertext
 * @param[in] in_selected index of the selection
 * @param[in] in_maxLimit number of commitments in the proof
 * @param[in] in_k The public key of the election
 * @param[in] in_q A value used when generating the challenge,
 *                 usually the election extended base hash (𝑄')
 * @param[out] out_handle A handle to an `eg_ranged_chaum_pedersen_proof_t`. 
 *                        Caller is responsible for lifecycle.
 */
EG_API eg_electionguard_status_t eg_ranged_chaum_pedersen_proof_make(
  eg_elgamal_ciphertext_t *in_message, eg_element_mod_q_t *in_r, uint64_t in_selected,
  uint64_t in_maxLimit, eg_element_mod_p_t *in_k, eg_element_mod_q_t *in_q,
  const char *in_hash_prefix, eg_ranged_chaum_pedersen_proof_t **out_handle);

/**
 * make function for a `RangedChaumPedersenProof`
 *
 * This overload accepts a seed value and calculates
 * proofs deterministically based on the seed. (slower, but reproduceable proofs)
 * @param[in] in_message The ciphertext message
 * @param[in] in_r The nonce used creating the ElGamal ciphertext
 * @param[in] in_selected index of the selection
 * @param[in] in_maxLimit number of commitments in the proof
 * @param[in] in_k The public key of the election
 * @param[in] in_q A value used when generating the challenge,
 *                 usually the election extended base hash (𝑄')
 * @param[in] in_seed Used to generate other random values here
 * @param[in] in_plaintext Zero or one
 * @param[out] out_handle A handle to an `eg_disjunctive_chaum_pedersen_proof_t`. 
 *                        Caller is responsible for lifecycle.
 */
EG_API eg_electionguard_status_t eg_ranged_chaum_pedersen_proof_make_deterministic(
  eg_elgamal_ciphertext_t *in_message, eg_element_mod_q_t *in_r, uint64_t in_selected,
  uint64_t in_maxLimit, eg_element_mod_p_t *in_k, eg_element_mod_q_t *in_q,
  const char *in_hash_prefix, eg_element_mod_q_t *in_seed,
  eg_ranged_chaum_pedersen_proof_t **out_handle);

/**
 * Validates a "ranged" Chaum-Pedersen [0...n] proof.
 *
 * @param[in] in_ciphertext The ciphertext message
 * @param[in] in_k The public key of the election
 * @param[in] in_q The extended base hash of the election
 */
EG_API eg_electionguard_status_t eg_ranged_chaum_pedersen_proof_is_valid(
  eg_ranged_chaum_pedersen_proof_t *handle, eg_elgamal_ciphertext_t *in_ciphertext,
  eg_element_mod_p_t *in_k, eg_element_mod_q_t *in_q, const char *in_hash_prefix,
  bool *out_is_valid);

#endif

#ifndef ConstantChaumPedersenProof

struct eg_constant_chaum_pedersen_proof_s;

/**
* The Constant Chaum PedersenProof is a Non-Interactive Zero-Knowledge Proof
* that represents the proof of satisfying the selection limit (that the voter has not over voted).
* The proof demonstrates that the elgamal accumulation of the encrypted selections
* on the ballot forms an aggregate contest encryption matches the combination of random nonces (R)
* used to encrypt the selections and that the encrypted values do not exceed the selection limit L.
*
* This object should not be made directly.  Use `eg_constant_chaum_pedersen_make`
*
* see: https://www.electionguard.vote/spec/0.95.0/5_Ballot_encryption/#proof-of-satisfying-the-selection-limit
*/
typedef struct eg_constant_chaum_pedersen_proof_s eg_constant_chaum_pedersen_proof_t;

// No constructor provided.  Use `eg_constant_chaum_pedersen_make`

EG_API eg_electionguard_status_t
eg_constant_chaum_pedersen_proof_free(eg_constant_chaum_pedersen_proof_t *handle);

/**
 * a in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModP pad.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_constant_chaum_pedersen_proof_get_pad(
  eg_constant_chaum_pedersen_proof_t *handle, eg_element_mod_p_t **out_element_ref);

/**
 * b in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModP data.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_constant_chaum_pedersen_proof_get_data(
  eg_constant_chaum_pedersen_proof_t *handle, eg_element_mod_p_t **out_element_ref);

/**
 * c in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModQ challenge.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_constant_chaum_pedersen_proof_get_challenge(
  eg_constant_chaum_pedersen_proof_t *handle, eg_element_mod_q_t **out_element_ref);

/**
 * v in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModQ response.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_constant_chaum_pedersen_proof_get_response(
  eg_constant_chaum_pedersen_proof_t *handle, eg_element_mod_q_t **out_element_ref);

/**
 * make function for a `ConstantChaumPedersenProof`
 *
 * @param[in] in_message The ciphertext message
 * @param[in] in_r The nonce used creating the ElGamal ciphertext
 * @param[in] in_k The public key of the election
 * @param[in] in_seed Used to generate other random values here
 * @param[in] in_hash_header Zero or one
 * @param[in] in_constant the value to prove
 * @param[out] out_handle A handle to an `eg_constant_chaum_pedersen_proof_t`. Caller is responsible for lifecycle.
 */
EG_API eg_electionguard_status_t eg_constant_chaum_pedersen_proof_make(
  eg_elgamal_ciphertext_t *in_message, eg_element_mod_q_t *in_r, eg_element_mod_p_t *in_k,
  eg_element_mod_q_t *in_seed, eg_element_mod_q_t *in_hash_header, uint64_t in_constant,
  bool in_should_use_precomputed_values, eg_constant_chaum_pedersen_proof_t **out_handle);

/**
 * Validates a "constant" Chaum-Pedersen (selection-limit) proof.
 *
 * @param[in] in_message The ciphertext message
 * @param[in] in_k The public key of the election
 * @param[in] in_q The extended base hash of the election
 */
EG_API bool eg_constant_chaum_pedersen_proof_is_valid(eg_constant_chaum_pedersen_proof_t *handle,
                                                      eg_elgamal_ciphertext_t *in_message,
                                                      eg_element_mod_p_t *in_k,
                                                      eg_element_mod_q_t *in_q);

#endif

#ifndef ChaumPedersenProof

struct eg_chaum_pedersen_proof_s;

/**
* The Generic Chaum PedersenProof is a Non-Interactive Zero-Knowledge Proof
* that represents the proof of knowing a secret value.
*
* The proof is used during decryption to prove that the guardains have shared knowledge
* of the election secret key. Note the secret key is not computed directly
* but instead each guardian computes a share of the secret key and consequently
* also computes a sahre of the proof.
*
* Produces a proof that a given value corresponds to a specific encryption.
* computes: 𝑀 =𝐴^𝑠𝑖 mod 𝑝 and 𝐾𝑖 = 𝑔^𝑠𝑖 mod 𝑝
*
* This object should not be made directly.  Use ChaumPedersenProof::make
*
* see: TODO: include spec link
*/
typedef struct eg_chaum_pedersen_proof_s eg_chaum_pedersen_proof_t;

// No constructor provided.  Use `eg_constant_chaum_pedersen_make`

EG_API eg_electionguard_status_t eg_chaum_pedersen_proof_free(eg_chaum_pedersen_proof_t *handle);

/**
 * a in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModP pad.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_chaum_pedersen_proof_get_pad(
  eg_chaum_pedersen_proof_t *handle, eg_element_mod_p_t **out_element_ref);

/**
 * b in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModP data.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_chaum_pedersen_proof_get_data(
  eg_chaum_pedersen_proof_t *handle, eg_element_mod_p_t **out_element_ref);

/**
 * c in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModQ challenge.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_chaum_pedersen_proof_get_challenge(
  eg_chaum_pedersen_proof_t *handle, eg_element_mod_q_t **out_element_ref);

/**
 * v in the spec
 * 
 * @param[out] out_element_ref An opaque pointer to the ElementModQ response.  
 *                           The value is a reference and is not owned by the caller
 */
EG_API eg_electionguard_status_t eg_chaum_pedersen_proof_get_response(
  eg_chaum_pedersen_proof_t *handle, eg_element_mod_q_t **out_element_ref);

EG_API eg_electionguard_status_t eg_chaum_pedersen_proof_make(
  eg_elgamal_ciphertext_t *in_commitment, eg_element_mod_q_t *in_challenge,
  eg_element_mod_q_t *in_response, eg_chaum_pedersen_proof_t **out_handle);

/**
 * Validates a "constant" Chaum-Pedersen (selection-limit) proof.
 *
 * @param[in] in_message The ciphertext message
 * @param[in] in_k The public key of the election
 * @param[in] in_q The extended base hash of the election
 */
EG_API bool eg_chaum_pedersen_proof_is_valid(eg_chaum_pedersen_proof_t *handle,
                                             eg_elgamal_ciphertext_t *in_message,
                                             eg_element_mod_p_t *in_k, eg_element_mod_p_t *in_m,
                                             eg_element_mod_q_t *in_q);

#endif

#ifdef __cplusplus
}
#endif
#endif /* __ELECTIONGUARD_CHAUM_PEDERSEN_H_INCLUDED__ */
