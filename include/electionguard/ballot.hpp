#ifndef __ELECTIONGUARD_CPP_BALLOT_HPP_INCLUDED__
#define __ELECTIONGUARD_CPP_BALLOT_HPP_INCLUDED__

#include "chaum_pedersen.hpp"
#include "crypto_hashable.hpp"
#include "election.hpp"
#include "elgamal.hpp"
#include "export.h"
#include "group.hpp"
#include "precompute_buffers.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace electionguard
{
    /// <summary>
    /// Enumeration used when marking a ballot as cast or spoiled
    /// </summary>
    enum class BallotBoxState {
        /// <summary>
        /// A ballot whose state is unknown to ElectionGuard
        /// and will not be included in any election results
        /// </summary>
        notset = 0,
        /// <summary>
        /// A ballot that has been explicitly cast
        /// </summary>
        cast = 1,
        /// <summary>
        /// A ballot that never included in the tally BUT included in election record
        /// - contents always decrypted and stored in plain text
        /// - always included in the verification site
        /// - used to be called spoiled
        /// </summary>
        challenged = 2,
        /// <summary>
        /// A ballot that never included in the tally
        /// - included in election record for verification
        /// - contents never decrypted
        /// - never included in the verification site
        /// - slightly new meaning of what spoiled is
        /// </summary>
        spoiled = 3,
        /// <summary>
        /// A ballot whose state is unknown to ElectionGuard
        /// and will not be included in any election results
        /// </summary>
        unknown = 999
    };

    /// <summary>
    /// Get a string representation of a BallotBoxState enum
    /// </summary>
    EG_API std::string getBallotBoxStateString(const BallotBoxState &value);

    /// <summary>
    /// Get a BallotBoxState enum from a string.
    /// <returns>BallotBoxState.unknown if the value cannot be resolved</returns>
    /// </summary>
    EG_API BallotBoxState getBallotBoxState(const std::string &value);

    typedef enum eg_contest_is_valid_result_e {
        SUCCESS = 0,
        OVERVOTE = 1,
        OVERVOTE_ERROR = 2,
        INVALID_OBJECT_ID_ERROR = 3,
        TOO_MANY_SELECTIONS_ERROR = 4,
    } eg_contest_is_valid_result_t;

    /// <summary>
    /// ExtendedData represents any arbitrary data expressible as a string with a length.
    ///
    /// This class is used primarily as a field to hold encrypted data on a
    /// contest, overvote data and writeins.
    /// </summary>
    struct ExtendedData {
      public:
        /// <summary>
        /// The string value
        /// </summary>
        std::string value;

        /// <summary>
        /// The length of the string value
        /// </summary>
        uint64_t length;

        ExtendedData(std::string value, uint64_t length) : value(value), length(length) {}

        /// <summary>
        /// Clone the value by making a deep copy and returning a new unique pointer
        /// </summary>
        std::unique_ptr<ExtendedData> clone() const
        {
            return std::make_unique<ExtendedData>(this->value, this->length);
        }
    };

    /// <summary>
    /// A BallotSelection represents an individual selection on a ballot.
    ///
    /// This class accepts a `vote` integer field which has no constraints
    /// in the ElectionGuard Data Specification, but is constrained logically
    /// in the application to resolve to `True` or `False`aka only 0 and 1 is
    /// supported for now.
    ///
    /// This class can also be designated as `isPlaceholderSelection` which has no
    /// context to the data specification but is useful for running validity checks internally
    ///
    /// an `extendedData` field exists to support any arbitrary data to be associated
    /// with the selection.  In practice, this field is the cleartext representation
    /// of a write-in candidate value.  In the current implementation these values are
    /// discarded when encrypting.
    /// </summary>
    class EG_API PlaintextBallotSelection
    {
      public:
        PlaintextBallotSelection(const PlaintextBallotSelection &other);
        PlaintextBallotSelection(PlaintextBallotSelection &&other);
        PlaintextBallotSelection(std::string objectId, uint64_t vote,
                                 bool isPlaceholderSelection = false, std::string writeIn = "");
        ~PlaintextBallotSelection();

        PlaintextBallotSelection &operator=(PlaintextBallotSelection other);
        PlaintextBallotSelection &operator=(PlaintextBallotSelection &&other);

        /// <summary>
        /// Get the objectId of the selection, which is the unique id for
        /// the selection in a specific contest described in the election manifest.
        /// </summary>
        std::string getObjectId() const;

        /// <summary>
        /// Get the plaintext vote
        /// </summary>
        uint64_t getVote() const;

        /// <summary>
        /// Determines if this is a placeholder selection
        /// </summary>
        bool getIsPlaceholder() const;

        ExtendedData *getExtendedData() const;

        /// <summary>
        /// an optional field holding the value of a write-in candidate
        /// </summary>
        std::string getWriteIn() const;

        /// <summary>
        /// Given a PlaintextBallotSelection validates that the object matches an expected object
        /// and that the plaintext value can resolve to a valid representation
        /// </summary>
        bool isValid(const std::string &expectedObjectId) const;

        /// <summary>
        /// Clone the value by making a deep copy and returning a new unique pointer
        /// </summary>
        std::unique_ptr<PlaintextBallotSelection> clone() const;

      private:
        class Impl;
#pragma warning(suppress : 4251)
        std::unique_ptr<Impl> pimpl;
    };

    /// <summary>
    /// A CiphertextBallotSelection represents an individual encrypted selection on a ballot.
    ///
    /// This class accepts a `description_hash` and a `ciphertext` as required parameters
    /// in its constructor.
    ///
    /// When a selection is encrypted, the `description_hash` and `ciphertext` required fields must
    /// be populated at construction however the `nonce` is also usually provided by convention.
    ///
    /// After construction, the `crypto_hash` field is populated automatically in the `__post_init__` cycle
    ///
    /// A consumer of this object has the option to discard the `nonce` and/or discard the `proof`,
    /// or keep both values.
    ///
    /// By discarding the `nonce`, the encrypted representation and `proof`
    /// can only be regenerated if the nonce was derived from the ballot's seed nonce.  If the nonce
    /// used for this selection is truly random, and it is discarded, then the proofs cannot be regenerated.
    ///
    /// By keeping the `nonce`, or deriving the selection nonce from the ballot nonce, an external system can
    /// regenerate the proofs on demand.  This is useful for storage or memory constrained systems.
    ///
    /// By keeping the `proof` the nonce is not required fotor verify the encrypted selection.
    /// </summary>
    class EG_API CiphertextBallotSelection : public CryptoHashable
    {
      public:
        CiphertextBallotSelection(const CiphertextBallotSelection &other);
        CiphertextBallotSelection(const CiphertextBallotSelection &&other);
        CiphertextBallotSelection(const std::string &objectId, uint64_t sequenceOrder,
                                  const ElementModQ &descriptionHash,
                                  std::unique_ptr<ElGamalCiphertext> ciphertext, bool isPlaceholder,
                                  std::unique_ptr<ElementModQ> nonce,
                                  std::unique_ptr<ElementModQ> cryptoHash,
                                  std::unique_ptr<DisjunctiveChaumPedersenProof> proof,
                                  std::unique_ptr<ElGamalCiphertext> extendedData = nullptr);
        ~CiphertextBallotSelection();

        CiphertextBallotSelection &operator=(CiphertextBallotSelection other);
        CiphertextBallotSelection &operator=(CiphertextBallotSelection &&other);

        /// <summary>
        /// Get the objectId of the selection, which is the unique id for
        /// the selection in a specific contest described in the election manifest.
        /// </summary>
        std::string getObjectId() const;

        /// <summary>
        /// Get the sequence order of the selection
        /// </summary>
        uint64_t getSequenceOrder() const;

        /// <summary>
        /// The hash of the string representation of the Selection Description from the election manifest
        /// </summary>
        ElementModQ *getDescriptionHash() const;

        /// <summary>
        /// Determines if this is a placeholder selection
        /// </summary>
        bool getIsPlaceholder() const;

        /// <summary>
        /// The encrypted representation of the vote field
        /// </summary>
        ElGamalCiphertext *getCiphertext() const;

        /// <summary>
        /// The hash of the encrypted values
        /// </summary>
        ElementModQ *getCryptoHash() const;

        /// <summary>
        /// The nonce used to generate the encryption. Sensitive &amp; should be treated as a secret
        /// </summary>
        ElementModQ *getNonce() const;

        /// <summary>
        /// The proof that demonstrates the selection is an encryption of 0 or 1,
        /// and was encrypted using the `nonce`
        /// </summary>
        DisjunctiveChaumPedersenProof *getProof() const;

        /// <summary>
        /// Given an encrypted BallotSelection, generates a hash, suitable for rolling up
        /// into a hash / tracking code for an entire ballot. Of note, this particular hash examines
        /// the `encryptionSeed` and `message`, but not the proof.
        /// This is deliberate, allowing for the possibility of ElectionGuard variants running on
        /// much more limited hardware, wherein the Disjunctive Chaum-Pedersen proofs might be computed
        /// later on.
        ///
        /// In most cases the encryption_seed should match the `description_hash`
        /// </summary>
        virtual std::unique_ptr<ElementModQ> crypto_hash() const override;

        /// <summary>
        /// Constructs a `CipherTextBallotSelection` object. Most of the parameters here match up to fields
        /// in the class, but this helper function will compute a Chaum-Pedersen proof
        /// using the faster non-deterministic method. Likewise, if a crypto_hash is not provided,
        /// it will be derived from the other fields.
        ///</summary>
        static std::unique_ptr<CiphertextBallotSelection>
        make(const std::string &objectId, uint64_t sequenceOrder,
             const ElementModQ &descriptionHash, std::unique_ptr<ElGamalCiphertext> ciphertext,
             const CiphertextElectionContext &context, uint64_t plaintext,
             bool isPlaceholder = false, bool computeProof = true,
             std::unique_ptr<ElementModQ> nonce = nullptr,
             std::unique_ptr<ElementModQ> cryptoHash = nullptr,
             std::unique_ptr<ElGamalCiphertext> extendedData = nullptr);

        /// <summary>
        /// Constructs a `CipherTextBallotSelection` object. Most of the parameters here match up to fields
        /// in the class, but this helper function will compute a Chaum-Pedersen proof if the
        /// given nonce isn't `None`. Likewise, if a crypto_hash is not provided, it will be derived from
        /// the other fields.
        ///</summary>
        static std::unique_ptr<CiphertextBallotSelection>
        make(const std::string &objectId, uint64_t sequenceOrder,
             const ElementModQ &descriptionHash, std::unique_ptr<ElGamalCiphertext> ciphertext,
             const CiphertextElectionContext &context, const ElementModQ &proofSeed,
             uint64_t plaintext, bool isPlaceholder = false,
             std::unique_ptr<ElementModQ> nonce = nullptr,
             std::unique_ptr<ElementModQ> cryptoHash = nullptr,
             std::unique_ptr<DisjunctiveChaumPedersenProof> proof = nullptr,
             std::unique_ptr<ElGamalCiphertext> extendedData = nullptr);

        /// <summary>
        /// Constructs a `CipherTextBallotSelection` object. Most of the parameters here match up to fields
        /// in the class, but this helper function will compute a Chaum-Pedersen proof if the
        /// given nonce isn't `None`. Likewise, if a crypto_hash is not provided, it will be derived from
        /// the other fields.
        ///</summary>
        static std::unique_ptr<CiphertextBallotSelection>
        make(const std::string &objectId, uint64_t sequenceOrder,
             const ElementModQ &descriptionHash, std::unique_ptr<ElGamalCiphertext> ciphertext,
             const CiphertextElectionContext &context,
             std::unique_ptr<PrecomputedSelection> precomputedValues, uint64_t plaintext,
             bool isPlaceholder = false, std::unique_ptr<ElementModQ> cryptoHash = nullptr,
             bool computeProof = true, std::unique_ptr<ElGamalCiphertext> extendedData = nullptr);

        /// <sumary>
        /// Given an encrypted BallotSelection, validates the encryption state against a specific seed hash and public key.
        /// Calling this function expects that the object is in a well-formed encrypted state
        /// with the elgamal encrypted `message` field populated along with
        /// the DisjunctiveChaumPedersenProof`proof` populated.
        /// the ElementModQ `description_hash` and the ElementModQ `crypto_hash` are also checked.
        ///
        /// <param name="encryptionSeed">The hash of the SelectionDescription, or
        ///                         whatever `ElementModQ` was used to populate the `description_hash` field. </param>
        /// <param name="elgamalPublicKey">The election public key</param>
        /// <param name="cryptoExtendedBaseHash">The extended base hash of the election</param>
        /// </summary>
        bool isValidEncryption(const ElementModQ &encryptionSeed,
                               const ElementModP &elgamalPublicKey,
                               const ElementModQ &cryptoExtendedBaseHash);

        /// <sumary>
        /// reset the nonce value
        /// </summary>
        void resetNonce() const;

      private:
        class Impl;
#pragma warning(suppress : 4251)
        std::unique_ptr<Impl> pimpl;

        /// set the hash of the encrypted values.
        /// used when reconstrcuting objects from cache
        // TODO: void setCryptoHash(ElementModQ *cryptoHash);

        /// The nonce used to generate the encryption.
        /// Sensitive & should be treated as a secret
        //TODO: void setNonce(ElementModQ *nonce);
    };

    /// <summary>
    /// A PlaintextBallotContest represents the selections made by a voter for a specific ContestDescription
    ///
    /// This class can be either a partial or a complete representation of a contest dataset.  Specifically,
    /// a partial representation must include at a minimum the "affirmative" selections of a contest.
    /// A complete representation of a ballot must include both affirmative and negative selections of
    /// the contest, AND the placeholder selections necessary to satisfy the ConstantChaumPedersen proof
    /// in the CiphertextBallotContest.
    ///
    /// Typically partial contests may be passed into Electionguard for memory constrained systems,
    /// while complete contests are passed into ElectionGuard when running encryption on an existing dataset.
    /// </summary>
    class EG_API PlaintextBallotContest
    {
      public:
        PlaintextBallotContest(const PlaintextBallotContest &other);
        PlaintextBallotContest(PlaintextBallotContest &&other);
        PlaintextBallotContest(const std::string &objectId,
                               std::vector<std::unique_ptr<PlaintextBallotSelection>> selections);
        ~PlaintextBallotContest();

        PlaintextBallotContest &operator=(PlaintextBallotContest other);
        PlaintextBallotContest &operator=(PlaintextBallotContest &&other);

        /// <summary>
        /// Get the objectId of the contest, which is the unique id for
        /// the contest in a specific ballot style described in the election manifest.
        /// </summary>
        std::string getObjectId() const;

        /// <summary>
        /// The collection of selections for this ballot contest
        /// </summary>
        std::vector<std::reference_wrapper<PlaintextBallotSelection>> getSelections() const;

        /// <summary>
        /// Given a PlaintextBallotContest returns true if the state is representative of the expected values.
        ///
        /// Note: because this class supports partial representations, undervotes are considered a valid state.
        /// </summary>
        eg_contest_is_valid_result_t isValid(const std::string &expectedObjectId,
                                             uint64_t expectedNumberSelections,
                                             uint64_t expectedNumberElected,
                                             uint64_t votesAllowd = 0,
                                             bool supportOvervotes = true) const;

      private:
        class Impl;
#pragma warning(suppress : 4251)
        std::unique_ptr<Impl> pimpl;
    };

    /// <summary>
    /// A CiphertextBallotContest represents the selections made by a voter for a specific ContestDescription
    ///
    /// CiphertextBallotContest can only be a complete representation of a contest dataset.  While
    /// PlaintextBallotContest supports a partial representation, a CiphertextBallotContest includes all data
    /// necessary for a verifier to verify the contest.  Specifically, it includes both explicit affirmative
    /// and negative selections of the contest, as well as the placeholder selections that satisfy
    /// the ConstantChaumPedersen proof.
    ///
    /// Similar to `CiphertextBallotSelection` the consuming application can choose to discard or keep both
    /// the `nonce` and the `proof` in some circumstances.  For deterministic nonce's derived from the
    /// seed nonce, both values can be regenerated.  If the `nonce` for this contest is completely random,
    /// then it is required in order to regenerate the proof.
    /// </summary>
    class EG_API CiphertextBallotContest : public CryptoHashable
    {
      public:
        CiphertextBallotContest(const CiphertextBallotContest &other);
        CiphertextBallotContest(const CiphertextBallotContest &&other);
        CiphertextBallotContest(const std::string &objectId, uint64_t sequenceOrder,
                                const ElementModQ &descriptionHash,
                                std::vector<std::unique_ptr<CiphertextBallotSelection>> selections,
                                std::unique_ptr<ElementModQ> nonce,
                                std::unique_ptr<ElGamalCiphertext> ciphertextAccumulation,
                                std::unique_ptr<ElementModQ> cryptoHash,
                                std::unique_ptr<RangedChaumPedersenProof> proof,
                                std::unique_ptr<HashedElGamalCiphertext> hashedElGamal);
        ~CiphertextBallotContest();

        CiphertextBallotContest &operator=(CiphertextBallotContest other);
        CiphertextBallotContest &operator=(CiphertextBallotContest &&other);

        /// <summary>
        /// Get the objectId of the contest, which is the unique id for
        /// the contest in a specific ballot style described in the election manifest.
        /// </summary>
        std::string getObjectId() const;

        /// <summary>
        /// Get the sequence order of the contest
        /// </summary>
        uint64_t getSequenceOrder() const;

        /// <summary>
        /// The hash of the string representation of the Contest Description from the election manifest
        /// </summary>
        ElementModQ *getDescriptionHash() const;

        /// <summary>
        /// Collection of ballot selections
        /// </summary>
        std::vector<std::reference_wrapper<CiphertextBallotSelection>> getSelections() const;

        /// <summary>
        /// The nonce used to generate the encryption. Sensitive & should be treated as a secret
        /// </summary>
        ElementModQ *getNonce() const;

        /// <summary>
        /// The encrypted representation of all of the vote fields (the contest total)
        /// </summary>
        ElGamalCiphertext *getCiphertextAccumulation() const;

        /// <summary>
        /// Hash of the encrypted values
        /// </summary>
        ElementModQ *getCryptoHash() const;

        /// <summary>
        /// The proof demonstrates the sum of the selections does not exceed the maximum
        /// available selections for the contest, and that the proof was generated with the nonce
        /// </summary>
        RangedChaumPedersenProof *getProof() const;

        /// <summary>
        /// The hashed elgamal ciphertext is the encrypted extended data (overvote information
        /// and writeins).
        /// </summary>
        std::unique_ptr<HashedElGamalCiphertext> getHashedElGamalCiphertext() const;

        /// <summary>
        /// Given an encrypted BallotContest, generates a hash, suitable for rolling up
        /// into a hash / tracking code for an entire ballot. Of note, this particular hash examines
        /// the `encryptionSeed` and `ballot_selections`, but not the proof.
        /// This is deliberate, allowing for the possibility of ElectionGuard variants running on
        /// much more limited hardware, wherein the Disjunctive Chaum-Pedersen proofs might be computed
        /// later on.
        ///
        /// In most cases, the encryption_seed is the description_hash
        /// </summary>
        virtual std::unique_ptr<ElementModQ> crypto_hash() const override;

        /// <summary>
        /// Constructs a `CipherTextBallotContest` object. Most of the parameters here match up to fields
        /// in the class, but this helper function will optionally compute a Chaum-Pedersen proof if the
        /// ballot selections include their encryption nonces. Likewise, if a crypto_hash is not provided,
        /// it will be derived from the other fields.
        /// </summary>
        static std::unique_ptr<CiphertextBallotContest>
        make(const std::string &objectId, uint64_t sequenceOrder,
             const ElementModQ &descriptionHash,
             std::vector<std::unique_ptr<CiphertextBallotSelection>> selections,
             const CiphertextElectionContext &context, const ElementModQ &proofSeed,
             const uint64_t numberSelected, const uint64_t numberElected,
             std::unique_ptr<ElementModQ> nonce = nullptr,
             std::unique_ptr<ElementModQ> cryptoHash = nullptr,
             std::unique_ptr<RangedChaumPedersenProof> proof = nullptr,
             std::unique_ptr<HashedElGamalCiphertext> hashedElGamal = nullptr);

        /// <summary>
        /// An aggregate nonce for the contest composed of the nonces of the selections.
        /// Used when constructing the proof of selection limit
        /// </summary>
        std::unique_ptr<ElementModQ> aggregateNonce() const;

        /// <summary>
        /// Add the individual ballot_selections `message` fields together, suitable for use
        /// when constructing the proof of selection limit.
        /// </summary>
        std::unique_ptr<ElGamalCiphertext> elgamalAccumulate() const;

        /// <summary>
        /// Genmerate the contest nonce
        /// </summary>
        static std::unique_ptr<ElementModQ> contestNonce(const CiphertextElectionContext &context,
                                                         uint64_t sequenceOrder,
                                                         const ElementModQ &nonce);

        /// <summary>
        /// Given an encrypted BallotContest, validates the encryption state against
        /// a specific encryption seed and public key
        /// by verifying the accumulated sum of selections match the proof.
        /// Calling this function expects that the object is in a well-formed encrypted state
        /// with the `ballot_selections` populated with valid encrypted ballot selections,
        /// the ElementModQ `description_hash`, the ElementModQ `crypto_hash`,
        /// and the RangedChaumPedersenProof all populated.
        /// Specifically, the seed hash in this context is the hash of the ContestDescription,
        /// or whatever `ElementModQ` was used to populate the `description_hash` field.
        /// </summary>
        bool isValidEncryption(const ElementModQ &encryptionSeed,
                               const ElementModP &elgamalPublicKey,
                               const ElementModQ &cryptoExtendedBaseHash);

      protected:
        static std::unique_ptr<ElementModQ> makeCryptoHash(
          const CiphertextElectionContext &context, uint64_t sequenceOrder,
          const std::vector<std::reference_wrapper<CiphertextBallotSelection>> &selections);
        static std::unique_ptr<ElementModQ> makeCryptoHash(
          const ElementModP &elgamalPublicKey, const ElementModQ &cryptoExtendedBaseHash,
          uint64_t sequenceOrder,
          const std::vector<std::reference_wrapper<CiphertextBallotSelection>> &selections);
        static std::unique_ptr<ElementModQ> aggregateNonce(
          const std::vector<std::reference_wrapper<CiphertextBallotSelection>> &selections);
        static std::unique_ptr<ElGamalCiphertext> elgamalAccumulate(
          const std::vector<std::reference_wrapper<CiphertextBallotSelection>> &selections);

      private:
        class Impl;
#pragma warning(suppress : 4251)
        std::unique_ptr<Impl> pimpl;
    };

    /// <summary>
    /// A PlaintextBallot represents a voters selections for a given ballot and ballot style.
    ///
    /// This class can be either a partial or a complete representation of the expected values of a ballot dataset.
    /// Specifically, a partial representation must include at a minimum the "affirmative" selections
    /// of every contest where a selection is made.  A partial representation may exclude contests for which
    /// no selection is made.
    ///
    /// A complete representation of a ballot must include both affirmative and negative selections of
    /// every contest, AND the placeholder selections necessary to satisfy the NIZKPs for each contest and selection.
    /// </summary>
    class EG_API PlaintextBallot
    {
      public:
        PlaintextBallot(const PlaintextBallot &other);
        PlaintextBallot(const PlaintextBallot &&other);
        PlaintextBallot(const std::string &objectId, const std::string &styleId,
                        std::vector<std::unique_ptr<PlaintextBallotContest>> contests);
        ~PlaintextBallot();

        PlaintextBallot &operator=(PlaintextBallot other);
        PlaintextBallot &operator=(PlaintextBallot &&other);

        /// <summary>
        /// A unique Ballot ID that is relevant to the external system and must be unique
        /// within the dataset of the election.
        /// </summary>
        std::string getObjectId() const;

        /// <summary>
        /// The Object Id of the ballot style in the election manifest.  This value is used
        /// to determine which contests to expect on the ballot, to fill in missing values,
        /// and to validate that the ballot is well-formed
        /// </summary>
        std::string getStyleId() const;

        /// <summary>
        /// The collection of contests on the ballot
        /// </summary>
        std::vector<std::reference_wrapper<PlaintextBallotContest>> getContests() const;

        /// <summary>
        /// Export the ballot representation as BSON
        /// </summary>
        std::vector<uint8_t> toBson() const;

        /// <summary>
        /// Export the ballot representation as JSON
        /// </summary>
        std::string toJson() const;

        /// <summary>
        /// Export the ballot representation as MsgPack
        /// </summary>
        std::vector<uint8_t> toMsgPack() const;

        /// <summary>
        /// Import the ballot representation from BSON
        /// </summary>
        static std::unique_ptr<PlaintextBallot> fromBson(std::vector<uint8_t> data);

        /// <summary>
        /// Creates a <see cref="PlaintextBallot">PlaintextBallot</see> object from a <see href="https://www.rfc-editor.org/rfc/rfc8259.html#section-8.1">[RFC-8259]</see> UTF-8 encoded JSON string
        /// </summary>
        /// <param name="data">A UTF-8 Encoded JSON data string</param>
        /// <returns>
        /// A unique pointer to a <see cref="PlaintextBallot">PlaintextBallot</see> Object
        /// </returns>
        static std::unique_ptr<PlaintextBallot> fromJson(std::string data);

        /// <summary>
        /// Import the ballot representation from MsgPack
        /// </summary>
        static std::unique_ptr<PlaintextBallot> fromMsgPack(std::vector<uint8_t> data);

      private:
        class Impl;
#pragma warning(suppress : 4251)
        std::unique_ptr<Impl> pimpl;
    };

    /// <summary>
    /// A CiphertextBallot represents a voters encrypted selections for a given ballot and ballot style.
    ///
    /// When a ballot is in it's complete, encrypted state, the `nonce` is the seed nonce
    /// from which all other nonces can be derived to encrypt the ballot.  Allong with the `nonce`
    /// fields on `Ballotcontest` and `BallotSelection`, this value is sensitive.
    ///
    /// Don't make this directly. Use `make_ciphertext_ballot` instead.
    /// </summary>
    class EG_API CiphertextBallot : public CryptoHashable
    {
      public:
        CiphertextBallot(const CiphertextBallot &other);
        CiphertextBallot(const CiphertextBallot &&other);
        CiphertextBallot(const std::string &objectId, const std::string &styleId,
                         const ElementModQ &manifestHash,
                         std::unique_ptr<ElementModQ> ballotCodeSeed,
                         std::vector<std::unique_ptr<CiphertextBallotContest>> contests,
                         std::unique_ptr<ElementModQ> ballotCode, const uint64_t timestamp,
                         std::unique_ptr<ElementModQ> nonce,
                         std::unique_ptr<ElementModQ> cryptoHash,
                         BallotBoxState state = BallotBoxState::unknown);
        ~CiphertextBallot();

        CiphertextBallot &operator=(CiphertextBallot other);
        CiphertextBallot &operator=(CiphertextBallot &&other);

        /// <summary>
        /// The unique ballot id that is meaningful to the consuming application.
        /// </summary>
        std::string getObjectId() const;

        /// <summary>
        /// The Object Id of the ballot style in the election manifest.  This value is used
        /// to determine which contests to expect on the ballot, to fill in missing values,
        /// and to validate that the ballot is well-formed
        /// </summary>
        std::string getStyleId() const;

        /// <summary>
        /// The state of the ballot (cast, spoiled, or unknown)
        /// </summary>
        BallotBoxState getState() const;

        /// <summary>
        /// Hash of the complete Election Manifest to which this ballot belongs
        /// </summary>
        ElementModQ *getManifestHash() const;

        /// <summary>
        /// The seed hash for the ballot.  It may be the encryption device hash,
        /// the hash of a previous ballot or the hash of some other value
        /// that is meaningful to the consuming application.
        /// </summary>
        ElementModQ *getBallotCodeSeed() const;

        /// <summary>
        /// The collection of contests for this ballot
        /// </summary>
        std::vector<std::reference_wrapper<CiphertextBallotContest>> getContests() const;

        /// <summary>
        /// The unique ballot code for this ballot that is derived from
        /// the ballot seed, the timestamp, and the hash of the encrypted values
        /// </summary>
        ElementModQ *getBallotCode() const;

        /// <summary>
        /// The timestamp indicating when the ballot was encrypted
        /// as measured by the encryption device.  This value does not
        /// provide units as it is up to the host system to indicate the scale.
        /// Typically a host may use seconds since epoch or ticks since epoch
        /// </summary>
        uint64_t getTimestamp() const;

        /// <summary>
        /// The nonce value used to encrypt all values in the ballot.
        /// Sensitive & should be treated as a secret
        /// </summary>
        ElementModQ *getNonce() const;

        /// <summary>
        /// The hash of the encrypted values on this ballot in sequence order
        /// this method is deprecated in favor of crypto_hash
        /// </summary>
        ElementModQ *getCryptoHash() const;

        /// <summary>
        /// Given an encrypted Ballot, generates a hash, suitable for rolling up
        /// into a hash for an entire ballot / ballot code. Of note, this particular hash examines
        /// the `manifest_hash` and `ballot_selections`, but not the proof.
        /// This is deliberate, allowing for the possibility of ElectionGuard variants running on
        /// much more limited hardware, wherein the Disjunctive Chaum-Pedersen proofs might be computed
        /// later on.
        /// </summary>
        virtual std::unique_ptr<ElementModQ> crypto_hash() const override;

        /// <summary>
        /// Makes a `CiphertextBallot`, initially in the state where it's neither been cast nor spoiled.
        ///
        /// <param name="objectId"> the object_id of this specific ballot</param>
        /// <param name="styleId"> The `object_id` of the `StyleId` in the `Election` Manifest</param>
        /// <param name="manifestHash"> Hash of the election manifest</param>
        /// <param name="nonce"> optional nonce used as part of the encryption process</param>
        /// <param name="contests"> List of contests for this ballot</param>
        /// <param name="timestamp"> Timestamp at which the ballot encryption is generated in tick.
        ///                          Will use the system time if none provided</param>
        /// <param name="ballotCode"> Previous ballot code or seed.
        ///                           Will use the manifestHash if none provided</param>
        /// </summary>
        static std::unique_ptr<CiphertextBallot>
        make(const std::string &objectId, const std::string &styleId,
             const ElementModQ &manifestHash, const CiphertextElectionContext &context,
             std::vector<std::unique_ptr<CiphertextBallotContest>> contests,
             std::unique_ptr<ElementModQ> nonce = nullptr, const uint64_t timestamp = 0,
             std::unique_ptr<ElementModQ> ballotCodeSeed = nullptr,
             std::unique_ptr<ElementModQ> ballotCode = nullptr,
             BallotBoxState state = BallotBoxState::unknown, const std::string &aux = "");

        /// <summary>
        /// A static helper method to derive the nonceSeed used to encrypt the ballot
        /// </summary>
        static std::unique_ptr<ElementModQ> nonceSeed(const ElementModQ &manifestHash,
                                                      const std::string &objectId,
                                                      const ElementModQ &nonce);

        bool isValidEncryption(const ElementModQ &manifestHash, const ElementModP &elgamalPublicKey,
                               const ElementModQ &cryptoExtendedBaseHash);

        /// <summary>
        /// Given an encrypted Ballot, validates the encryption state
        /// against a specific ballot seed and public key
        /// by verifying the states of this ballot's members (BallotContest's and BallotSelection's).
        /// Calling this function expects that the object is in a well-formed encrypted state
        /// with the `contests` populated with valid encrypted ballot selections,
        /// and the ElementModQ `manifest_hash` also populated.
        /// Specifically, the seed in this context is the hash of the Election Manifest,
        /// or whatever `ElementModQ` was used to populate the `manifest_hash` field.
        /// </summary>
        bool isValidEncryption(const ElementModQ &manifestHash, const ElementModP &elgamalPublicKey,
                               const ElementModQ &cryptoExtendedBaseHash, const std::string &aux);

        /// <summary>
        /// A sufficiently random value used to seed the nonces on the ballot.
        /// Can be generated by calling the static member nonceSeed(ElementModQ, std::string, ElementModQ)
        /// </summary>
        std::unique_ptr<ElementModQ> nonceSeed();

        /// <summary>
        /// A helper function to mark the ballot as cast and remove sensitive values like the nonce.
        /// </summary>
        void cast() const;

        /// <summary>
        /// A helper function to mark the ballot as spoiled and remove sensitive values like the nonce.
        /// </summary>
        void spoil() const;

        /// <summary>
        /// A helper function to mark the ballot as challenged and remove sensitive values like the nonce.
        /// </summary>
        void challenge() const;

        /// <summary>
        /// Export the ballot representation as BSON
        /// </summary>
        std::vector<uint8_t> toBson(bool withNonces = false) const;

        /// <summary>
        /// Export the ballot representation as JSON
        /// </summary>
        std::string toJson(bool withNonces = false) const;

        /// <summary>
        /// Export the ballot representation as MsgPack
        /// </summary>
        std::vector<uint8_t> toMsgPack(bool withNonces = false) const;

        /// <summary>
        /// Creates a <see cref="CiphertextBallot">CiphertextBallot</see> object from a <see href="https://www.rfc-editor.org/rfc/rfc8259.html#section-8.1">[RFC-8259]</see> UTF-8 encoded JSON string
        /// </summary>
        /// <param name="data">A UTF-8 Encoded JSON data string</param>
        /// <returns>
        /// A unique pointer to a <see cref="CiphertextBallot">CiphertextBallot</see> Object
        /// </returns>
        static std::unique_ptr<CiphertextBallot> fromJson(std::string data);

        /// <summary>
        /// Import the ballot representation from BSON
        /// </summary>
        static std::unique_ptr<CiphertextBallot> fromBson(std::vector<uint8_t> data);

        /// <summary>
        /// Import the ballot representation from MsgPack
        /// </summary>
        static std::unique_ptr<CiphertextBallot> fromMsgPack(std::vector<uint8_t> data);

      protected:
        static std::unique_ptr<ElementModQ>
        makeCryptoHash(const ElementModQ &extendedBaseHash,
                       const std::vector<std::reference_wrapper<CiphertextBallotContest>> &contests,
                       const std::string &aux);

      private:
        class Impl;
#pragma warning(suppress : 4251)
        std::unique_ptr<Impl> pimpl;
    };

    /// <summary>
    /// A `SubmittedBallot` represents a ballot that is submitted for inclusion in election results.
    /// A submitted ballot is or is about to be either cast or spoiled.
    /// The state supports the `BallotBoxState.UNKNOWN` enumeration to indicate that this object is mutable
    /// and has not yet been explicitly assigned a specific state.
    ///
    /// Note, additionally, this ballot includes all proofs but no nonces.
    ///
    /// Do not make this class directly. Use `make_ciphertext_submitted_ballot` or `from_ciphertext_ballot` instead.
    /// </summary>

    class EG_API SubmittedBallot : public CiphertextBallot
    {
      public:
        SubmittedBallot(const SubmittedBallot &other);
        SubmittedBallot(const SubmittedBallot &&other);
        explicit SubmittedBallot(const CiphertextBallot &other, BallotBoxState state);
        explicit SubmittedBallot(const std::string &objectId, const std::string &styleId,
                                 const ElementModQ &manifestHash,
                                 std::unique_ptr<ElementModQ> ballotCodeSeed,
                                 std::vector<std::unique_ptr<CiphertextBallotContest>> contests,
                                 std::unique_ptr<ElementModQ> ballotCode, const uint64_t timestamp,
                                 std::unique_ptr<ElementModQ> nonce,
                                 std::unique_ptr<ElementModQ> cryptoHash, BallotBoxState state);
        ~SubmittedBallot();

        SubmittedBallot &operator=(SubmittedBallot other) = delete;
        SubmittedBallot &operator=(SubmittedBallot &&other);

        /// <summary>
        /// Convert a `CiphertextBallot` into a `SubmittedBallot`, with all nonces removed.
        /// </summary>
        static std::unique_ptr<SubmittedBallot>
        from(const CiphertextBallot &ballot, BallotBoxState state = BallotBoxState::unknown);

        /// <summary>
        /// Makes a `SubmittedBallot`, initially in the state where it's neither been cast nor spoiled.
        ///
        /// <param name="objectId"> the object_id of this specific ballot</param>
        /// <param name="styleId"> The `object_id` of the `StyleId` in the `Election` Manifest</param>
        /// <param name="manifestHash"> Hash of the election manifest</param>
        /// <param name="nonce"> optional nonce used as part of the encryption process</param>
        /// <param name="contests"> List of contests for this ballot</param>
        /// <param name="timestamp"> Timestamp at which the ballot encryption is generated in tick.
        ///                          Will use the system time if none provided</param>
        /// <param name="ballotCode"> Previous ballot code or seed.
        ///                           Will use the manifestHash if none provided</param>
        /// <param name="contests"> List of contests for this ballot</param>
        /// </summary>
        static std::unique_ptr<SubmittedBallot>
        make(const std::string &objectId, const std::string &styleId,
             const ElementModQ &manifestHash, const CiphertextElectionContext &context,
             std::vector<std::unique_ptr<CiphertextBallotContest>> contests,
             std::unique_ptr<ElementModQ> nonce = nullptr, const uint64_t timestamp = 0,
             std::unique_ptr<ElementModQ> ballotCodeSeed = nullptr,
             std::unique_ptr<ElementModQ> ballotCode = nullptr,
             BallotBoxState state = BallotBoxState::unknown, const std::string &aux = "");

        /// <summary>
        /// Export the ballot representation as BSON
        /// </summary>
        std::vector<uint8_t> toBson() const;

        /// <summary>
        /// Export the ballot representation as JSON
        /// </summary>
        std::string toJson() const;

        /// <summary>
        /// Export the ballot representation as MsgPack
        /// </summary>
        std::vector<uint8_t> toMsgPack() const;

        /// <summary>
        /// Creates a <see cref="SubmittedBallot">SubmittedBallot</see> object from a <see href="https://www.rfc-editor.org/rfc/rfc8259.html#section-8.1">[RFC-8259]</see> UTF-8 encoded JSON string
        /// </summary>
        /// <param name="json">A UTF-8 Encoded JSON data string</param>
        /// <returns>
        /// A unique pointer to a <see cref="SubmittedBallot">SubmittedBallot</see> Object
        /// </returns>
        static std::unique_ptr<SubmittedBallot> fromJson(std::string data);

        /// <summary>
        /// Import the ballot representation from BSON
        /// </summary>
        static std::unique_ptr<SubmittedBallot> fromBson(std::vector<uint8_t> data);

        /// <summary>
        /// Import the ballot representation from MsgPack
        /// </summary>
        static std::unique_ptr<SubmittedBallot> fromMsgPack(std::vector<uint8_t> data);
    };

} // namespace electionguard

#endif /* __ELECTIONGUARD_CPP_BALLOT_HPP_INCLUDED__ */
