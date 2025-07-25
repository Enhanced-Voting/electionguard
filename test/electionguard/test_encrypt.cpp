#include "../../src/electionguard/log.hpp"
#include "generators/ballot.hpp"
#include "generators/election.hpp"
#include "generators/manifest.hpp"
#include "utils/constants.hpp"

#include <doctest/doctest.h>
#include <electionguard/ballot.hpp>
#include <electionguard/election.hpp>
#include <electionguard/encrypt.hpp>
#include <electionguard/hash.hpp>
#include <electionguard/manifest.hpp>

using namespace electionguard;
using namespace electionguard::tools::generators;
using namespace std;

TEST_CASE("Encrypt simple selection succeeds")
{
    // Arrange
    const auto *candidateId = "some-candidate-id";
    const auto *selectionId = "some-selection-object-id";
    auto keypair = ElGamalKeyPair::fromSecret(TWO_MOD_Q(), false);
    auto nonce = rand_q();
    auto metadata = make_unique<SelectionDescription>(selectionId, candidateId, 1UL);
    auto hashContext = metadata->crypto_hash();
    auto plaintext = BallotGenerator::selectionFrom(*metadata);
    auto context = CiphertextElectionContext::make(3, 2, keypair->getPublicKey()->clone(),
                                                   ONE_MOD_Q().clone(), ONE_MOD_Q().clone());

    // Act
    auto result = encryptSelection(*plaintext, *metadata, *context, *nonce, false, true);

    // Assert
    CHECK(result != nullptr);
    CHECK(result->getCiphertext() != nullptr);
    CHECK(result->isValidEncryption(*hashContext, *keypair->getPublicKey(),
                                    *context->getCryptoExtendedBaseHash()) == true);
    CHECK(result->getProof()->isValid(*result->getCiphertext(), *keypair->getPublicKey(),
                                      *context->getCryptoExtendedBaseHash()) == true);
}

TEST_CASE("Encrypt simple selection using precomputed values succeeds")
{
    // Arrange
    const auto *candidateId = "some-candidate-id";
    const auto *selectionId = "some-selection-object-id";
    auto keypair = ElGamalKeyPair::fromSecret(TWO_MOD_Q(), false);
    auto nonce = rand_q();
    auto metadata = make_unique<SelectionDescription>(selectionId, candidateId, 1UL);
    auto hashContext = metadata->crypto_hash();
    auto plaintext = BallotGenerator::selectionFrom(*metadata);
    auto context = CiphertextElectionContext::make(3, 2, keypair->getPublicKey()->clone(),
                                                   ONE_MOD_Q().clone(), ONE_MOD_Q().clone());

    // cause a two triples and a quad to be populated
    PrecomputeBufferContext::initialize(*keypair->getPublicKey(), 1);
    PrecomputeBufferContext::start();
    PrecomputeBufferContext::stop();

    uint32_t max_precomputed_queue_size = PrecomputeBufferContext::getMaxQueueSize();
    uint32_t current_precomputed_queue_size = PrecomputeBufferContext::getCurrentQueueSize();

    CHECK(1 == max_precomputed_queue_size);
    CHECK(1 == current_precomputed_queue_size);

    // and this ecryptSelection will use the precomputed values
    auto result = encryptSelection(*plaintext, *metadata, *context, *nonce, false, true);

    // Assert
    CHECK(result != nullptr);
    CHECK(result->getCiphertext() != nullptr);
    CHECK(result->isValidEncryption(*hashContext, *keypair->getPublicKey(),
                                    *context->getCryptoExtendedBaseHash()) == true);
    CHECK(result->getProof()->isValid(*result->getCiphertext(), *keypair->getPublicKey(),
                                      *context->getCryptoExtendedBaseHash()) == true);
    // need to empty the queues because future tests don't use the same keys
    PrecomputeBufferContext::clear();
}

TEST_CASE("Encrypt simple selection malformed data fails")
{
    // Arrange
    const auto *candidateId = "some-candidate-id";
    const auto *selectionId = "some-selection-object-id";
    auto keypair = ElGamalKeyPair::fromSecret(TWO_MOD_Q(), false);
    auto nonce = rand_q();
    auto metadata = make_unique<SelectionDescription>(selectionId, candidateId, 1UL);
    auto hashContext = metadata->crypto_hash();
    auto plaintext = BallotGenerator::selectionFrom(*metadata);
    auto context = CiphertextElectionContext::make(3, 2, keypair->getPublicKey()->clone(),
                                                   ONE_MOD_Q().clone(), ONE_MOD_Q().clone());

    // Act
    auto result = encryptSelection(*plaintext, *metadata, *context, *nonce, false, true);

    // tamper with the description_hash
    auto malformedDescriptionHash = make_unique<CiphertextBallotSelection>(
      result->getObjectId(), metadata->getSequenceOrder(), TWO_MOD_Q(),
      result->getCiphertext()->clone(), result->getIsPlaceholder(), result->getNonce()->clone(),
      result->getCryptoHash()->clone(), result->getProof()->clone());

    // remove the proof
    auto missingProof = make_unique<CiphertextBallotSelection>(
      result->getObjectId(), metadata->getSequenceOrder(), *result->getDescriptionHash(),
      result->getCiphertext()->clone(), result->getIsPlaceholder(), result->getNonce()->clone(),
      result->getCryptoHash()->clone(), nullptr);

    // Assert
    CHECK(result->isValidEncryption(*hashContext, *keypair->getPublicKey(),
                                    *context->getCryptoExtendedBaseHash()) == true);
    CHECK(malformedDescriptionHash->isValidEncryption(*hashContext, *keypair->getPublicKey(),
                                                      *context->getCryptoExtendedBaseHash()) ==
          false);
    CHECK(missingProof->isValidEncryption(*hashContext, *keypair->getPublicKey(),
                                          *context->getCryptoExtendedBaseHash()) == false);
}

TEST_CASE("Encrypt PlaintextBallot with EncryptionMediator against constructed "
          "InternalManifest succeeds")
{
    // Arrange
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto init = pow_mod_p(*keypair->getPublicKey(), *ElementModQ::fromUint64(1));
    auto manifest = ManifestGenerator::getJeffersonCountyManifest_Minimal();
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());
    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");

    auto mediator = make_unique<EncryptionMediator>(*internal, *context, *device);

    // // Act
    auto plaintext = BallotGenerator::getFakeBallot(*internal);
    Log::trace(plaintext->toJson());
    auto ciphertext = mediator->encrypt(*plaintext);

    // Assert
    CHECK(ciphertext->isValidEncryption(*context->getManifestHash(), *keypair->getPublicKey(),
                                        *context->getCryptoExtendedBaseHash()) == true);
    CHECK(ciphertext->getContests().front().get().getHashedElGamalCiphertext().get() != nullptr);
}

TEST_CASE("Encrypt PlaintextBallot undervote succeeds")
{
    // Arrange
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = ManifestGenerator::getJeffersonCountyManifest_Minimal();
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());
    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");

    auto mediator = make_unique<EncryptionMediator>(*internal, *context, *device);

    // Act
    auto plaintext = BallotGenerator::getFakeBallot(*internal, 0UL);
    Log::trace(plaintext->toJson());
    auto ciphertext = mediator->encrypt(*plaintext);

    // Assert
    CHECK(ciphertext->isValidEncryption(*context->getManifestHash(), *keypair->getPublicKey(),
                                        *context->getCryptoExtendedBaseHash()) == true);
}

TEST_CASE("Encrypt PlaintextBallot overvote")
{
    // Arrange
    const auto &secret = TWO_MOD_Q();
    auto keypair = ElGamalKeyPair::fromSecret(secret, false);
    auto manifest = ManifestGenerator::getJeffersonCountyManifest_Minimal();
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());
    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");

    auto mediator = make_unique<EncryptionMediator>(*internal, *context, *device);

    // Act
    auto plaintext = BallotGenerator::getFakeBallot(*internal, 2UL);
    //Log::debug(plaintext->toJson());

    auto ciphertext = mediator->encrypt(*plaintext);

    // Assert
    CHECK(ciphertext->isValidEncryption(*context->getManifestHash(), *keypair->getPublicKey(),
                                        *context->getCryptoExtendedBaseHash()) == true);

    // check to make sure we have a hashed elgamal ciphertext
    unique_ptr<HashedElGamalCiphertext> heg = nullptr;
    auto contests = ciphertext->getContests();
    for (auto contest : contests) {
        unique_ptr<CiphertextBallotContest> new_contest =
          make_unique<CiphertextBallotContest>(contest);
        auto id = new_contest->getObjectId();
        if (id == string("justice-supreme-court")) {
            heg = new_contest->getHashedElGamalCiphertext();
        }
    }

    CHECK(heg != nullptr);
    CHECK(heg->getData().size() == (size_t)(BYTES_512 + sizeof(uint16_t)));

    unique_ptr<ElementModP> new_pad = make_unique<ElementModP>(*heg->getPad());
    unique_ptr<HashedElGamalCiphertext> newHEG =
      make_unique<HashedElGamalCiphertext>(move(new_pad), heg->getData(), heg->getMac());

    vector<uint8_t> new_plaintext = newHEG->decrypt(*keypair->getPublicKey(), secret,
                                                    HashPrefix::get_prefix_contest_data_secret(),
                                                    *context->getCryptoExtendedBaseHash(), true);
    string new_plaintext_string((char *)&new_plaintext.front(), new_plaintext.size());

    CHECK(new_plaintext_string ==
          string("{\"error\":\"overvote\",\"error_data\":[\"benjamin-franklin-selection\""
                 ",\"john-adams-selection\"]}"));
}

TEST_CASE("Encrypt simple PlaintextBallot with EncryptionMediator succeeds")
{
    // Arrange
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = ManifestGenerator::getJeffersonCountyManifest_Minimal();
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());
    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");

    auto mediator = make_unique<EncryptionMediator>(*internal, *context, *device);

    // Act
    auto plaintext = BallotGenerator::getFakeBallot(*manifest);
    auto ciphertext = mediator->encrypt(*plaintext);

    // Assert
    CHECK(ciphertext->isValidEncryption(*context->getManifestHash(), *keypair->getPublicKey(),
                                        *context->getCryptoExtendedBaseHash()) == true);

    // Can Serialize CiphertextBallot
    auto json = ciphertext->toJson(); // as default values
    auto fromJson = CiphertextBallot::fromJson(json);
    CHECK(fromJson->getNonce()->toHex() == ZERO_MOD_Q().toHex());

    // serialize with nonce values
    auto jsonWithNonces = ciphertext->toJson(true);
    auto fromJsonWithNonces = CiphertextBallot::fromJson(jsonWithNonces);
    CHECK(fromJsonWithNonces->getNonce()->toHex() == ciphertext->getNonce()->toHex());

    CHECK(plaintext->getObjectId() == ciphertext->getObjectId());

    auto bson = ciphertext->toBson();
    auto fromBson = CiphertextBallot::fromBson(bson);
    CHECK(fromBson->getNonce()->toHex() == ZERO_MOD_Q().toHex());
}

TEST_CASE("Encrypt full PlaintextBallot with WriteIn and Overvote with EncryptionMediator succeeds")
{
    const auto &secret = TWO_MOD_Q();
    auto keypair = ElGamalKeyPair::fromSecret(secret, false);
    auto manifest = ManifestGenerator::getManifestFromFile(TEST_SPEC_VERSION, TEST_USE_FULL_SAMPLE);
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());
    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");

    auto mediator = make_unique<EncryptionMediator>(*internal, *context, *device);

    // Act
    string plaintextBallot_json = string(
      "{\"object_id\": \"03a29d15-667c-4ac8-afd7-549f19b8e4eb\","
      "\"style_id\": \"jefferson-county-ballot-style\", \"contests\": [ {\"object_id\":"
      "\"justice-supreme-court\", \"sequence_order\": 0, \"ballot_selections\": [{"
      "\"object_id\": \"john-adams-selection\", \"sequence_order\": 0, \"vote\": 1,"
      "\"is_placeholder_selection\": false, \"extended_data\": null}, {\"object_id\""
      ": \"benjamin-franklin-selection\", \"sequence_order\": 1, \"vote\": 1,"
      "\"is_placeholder_selection\": false, \"extended_data\": null}, {\"object_id\":"
      " \"write-in-selection\", \"sequence_order\": 3, \"vote\": 1, \"is_placeholder_selection\""
      ": false, \"write_in\": \"Susan B. Anthony\"}], \"extended_data\": null}]}");
    auto plaintextBallot = PlaintextBallot::fromJson(plaintextBallot_json);
    auto ciphertext = mediator->encrypt(*plaintextBallot);

    // Assert
    CHECK(ciphertext->isValidEncryption(*context->getManifestHash(), *keypair->getPublicKey(),
                                        *context->getCryptoExtendedBaseHash()) == true);

    // check to make sure we have a hashed elgamal ciphertext
    unique_ptr<HashedElGamalCiphertext> heg = nullptr;
    auto contests = ciphertext->getContests();
    for (auto contest : contests) {
        unique_ptr<CiphertextBallotContest> new_contest =
          make_unique<CiphertextBallotContest>(contest);
        auto id = new_contest->getObjectId();
        if (id == string("justice-supreme-court")) {
            heg = new_contest->getHashedElGamalCiphertext();
        }
    }

    CHECK(heg != nullptr);
    CHECK(heg->getData().size() == (size_t)(BYTES_512 + sizeof(uint16_t)));

    unique_ptr<ElementModP> new_pad = make_unique<ElementModP>(*heg->getPad());
    unique_ptr<HashedElGamalCiphertext> newHEG =
      make_unique<HashedElGamalCiphertext>(move(new_pad), heg->getData(), heg->getMac());

    vector<uint8_t> new_plaintext = newHEG->decrypt(*keypair->getPublicKey(), secret,
                                                    HashPrefix::get_prefix_contest_data_secret(),
                                                    *context->getCryptoExtendedBaseHash(), true);
    string new_plaintext_string((char *)&new_plaintext.front(), new_plaintext.size());
    Log::debug(new_plaintext_string);

    CHECK(new_plaintext_string ==
          string("{\"error\":\"overvote\",\"error_data\":[\"john-adams-selection\","
                 "\"benjamin-franklin-selection\",\"write-in-selection\"],\"write_ins\""
                 ":{\"write-in-selection\":\"Susan B. Anthony\"}}"));
}

TEST_CASE("Encrypt simple CompactPlaintextBallot with EncryptionMediator succeeds")
{
    // Arrange
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = ManifestGenerator::getJeffersonCountyManifest_Minimal();
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());
    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");
    auto mediator = make_unique<EncryptionMediator>(*internal, *context, *device);
    auto plaintext = BallotGenerator::getFakeBallot(*internal);

    // Act
    auto compactCiphertext = mediator->compactEncrypt(*plaintext);

    // Assert
    CHECK(compactCiphertext->getObjectId() == plaintext->getObjectId());
}

TEST_CASE("Encrypt simple ballot from file with mediator succeeds")
{
    // Arrange
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = ManifestGenerator::getManifestFromFile(TEST_SPEC_VERSION, TEST_USE_SAMPLE);
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());

    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");
    auto mediator = make_unique<EncryptionMediator>(*internal, *context, *device);
    auto ballot = BallotGenerator::getFakeBallot(*internal);

    // Act
    auto ciphertext = mediator->encrypt(*ballot);

    // Assert
    CHECK(ciphertext->isValidEncryption(*context->getManifestHash(), *keypair->getPublicKey(),
                                        *context->getCryptoExtendedBaseHash()) == true);
}

TEST_CASE("Encrypt simple ballot from file succeeds")
{
    // Arrange
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = ManifestGenerator::getManifestFromFile(TEST_SPEC_VERSION, TEST_USE_SAMPLE);
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());

    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");

    auto ballot = BallotGenerator::getFakeBallot(*internal);

    // Act
    auto ciphertext = encryptBallot(*ballot, *internal, *context, *device->getHash(),
                                    make_unique<ElementModQ>(TWO_MOD_Q()));

    //Log::debug(ciphertext->toJson());

    // Assert
    CHECK(ciphertext->isValidEncryption(*context->getManifestHash(), *keypair->getPublicKey(),
                                        *context->getCryptoExtendedBaseHash()) == true);
}

TEST_CASE("Encrypt simple ballot from file re-encrypt creates same ballot")
{
    // Arrange
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = ManifestGenerator::getManifestFromFile(TEST_SPEC_VERSION, TEST_USE_SAMPLE);
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());

    auto ballot = BallotGenerator::getFakeBallot(*internal);
    auto codeSeed = TWO_MOD_Q();

    // Act
    auto ciphertext = encryptBallot(*ballot, *internal, *context, codeSeed);
    auto timestamp = ciphertext->getTimestamp();
    auto nonce = ciphertext->getNonce();

    auto reencrypted =
      encryptBallot(*ballot, *internal, *context, codeSeed, nonce->clone(), timestamp);

    //Log::debug(ciphertext->toJson());

    // Assert
    CHECK(*ciphertext->getBallotCode() == *reencrypted->getBallotCode());
}

TEST_CASE(
  "Encrypt simple ballot from file using precompute tables re-encrypt creates a different ballot")
{
    // Arrange
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = ManifestGenerator::getManifestFromFile(TEST_SPEC_VERSION, TEST_USE_SAMPLE);
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());

    auto ballot = BallotGenerator::getFakeBallot(*internal);
    auto codeSeed = TWO_MOD_Q();

    auto verifyProofs = true;
    auto usePrecomputed = true;

    // fill the precompute table
    PrecomputeBufferContext::initialize(*keypair->getPublicKey(), 100);
    PrecomputeBufferContext::start();

    // Act
    auto ciphertext = encryptBallot(*ballot, *internal, *context, codeSeed, nullptr, 0,
                                    verifyProofs, usePrecomputed);
    auto timestamp = ciphertext->getTimestamp();
    auto nonce = ciphertext->getNonce();

    auto reencrypted = encryptBallot(*ballot, *internal, *context, codeSeed, nonce->clone(),
                                     timestamp, verifyProofs, false);

    // Assert
    CHECK(ciphertext->getBallotCode()->toHex() != reencrypted->getBallotCode()->toHex());
}

TEST_CASE("Encrypt simple ballot from file cast is valid")
{
    // Arrange
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = ManifestGenerator::getManifestFromFile(TEST_SPEC_VERSION, TEST_USE_SAMPLE);
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());
    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");

    auto ballot = BallotGenerator::getFakeBallot(*internal);

    // Act
    auto ciphertext = encryptBallot(*ballot, *internal, *context, *device->getHash());
    ciphertext->cast();

    // Assert
    CHECK(ciphertext->getNonce() == nullptr);
}

TEST_CASE("Encrypt simple ballot from file submitted is valid")
{
    // Arrange
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = ManifestGenerator::getManifestFromFile(TEST_SPEC_VERSION, TEST_USE_SAMPLE);
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());
    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");

    auto ballot = BallotGenerator::getFakeBallot(*internal);

    // Act
    auto ciphertext = encryptBallot(*ballot, *internal, *context, *device->getHash());

    auto submitted = SubmittedBallot::from(*ciphertext, BallotBoxState::cast);
    auto serialized = submitted->toJson();

    //Log::debug(serialized);
    auto deserialized = SubmittedBallot::fromJson(serialized);

    // Assert
    // TODO: compare other values
    CHECK(submitted->isValidEncryption(*context->getManifestHash(), *keypair->getPublicKey(),
                                       *context->getCryptoExtendedBaseHash()) == true);
    CHECK(deserialized->isValidEncryption(*context->getManifestHash(), *keypair->getPublicKey(),
                                          *context->getCryptoExtendedBaseHash()) == true);
}

TEST_CASE("Submit multiple ballots")
{
    auto ballotData =
      "{\"object_id\": \"ballot-434ab8e7-22f7-11ed-8bad-04d9f5218a21\", \"style_id\": "
      "\"e3505391-aca6-4666-aadf-4fb31357170b\", \"contests\": [{\"object_id\": "
      "\"9e5ca147-8f8a-414c-86c9-fa3b6c45754b\", \"ballot_selections\": [{\"object_id\": "
      "\"9e5ca147-8f8a-414c-86c9-fa3b6c45754b-5cf0794a-22ba-42c3-90d4-d23df7e221c1\", \"vote\": 0, "
      "\"is_placeholder_selection\": false, \"write_in\": null}, {\"object_id\": "
      "\"9e5ca147-8f8a-414c-86c9-fa3b6c45754b-8a3a7be9-fc51-4b50-b845-de268d268c0e\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}, {\"object_id\": "
      "\"9e5ca147-8f8a-414c-86c9-fa3b6c45754b-c9be49a1-1060-4318-935f-344fa96901c7\", \"vote\": 0, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"716043f6-3e08-43e1-9652-a2364bb3a170\", \"ballot_selections\": [{\"object_id\": "
      "\"716043f6-3e08-43e1-9652-a2364bb3a170-5684632f-e4e9-4ce4-bddc-ff83e7835511\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"98402323-e396-4f83-bc86-266cc583781d\", \"ballot_selections\": [{\"object_id\": "
      "\"98402323-e396-4f83-bc86-266cc583781d-016dd1a3-9099-4359-93bd-2e197d4ec424\", \"vote\": 0, "
      "\"is_placeholder_selection\": false, \"write_in\": null}, {\"object_id\": "
      "\"98402323-e396-4f83-bc86-266cc583781d-997c30fa-5e7f-46c5-ba2c-b974d099db1a\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"a888ca92-5ae2-42b3-a342-9fb6d1a76689\", \"ballot_selections\": [{\"object_id\": "
      "\"a888ca92-5ae2-42b3-a342-9fb6d1a76689-47179eb7-d042-44d8-aed7-e8011087c591\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}, {\"object_id\": "
      "\"a888ca92-5ae2-42b3-a342-9fb6d1a76689-81b8380b-8a44-497c-a9c8-83fe8258670e\", \"vote\": 0, "
      "\"is_placeholder_selection\": false, \"write_in\": null}, {\"object_id\": "
      "\"a888ca92-5ae2-42b3-a342-9fb6d1a76689-8902f19c-0802-42d8-a532-23fa5a95bc43\", \"vote\": 0, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"5347bea6-8112-4ffc-bfff-375656d45106\", \"ballot_selections\": [{\"object_id\": "
      "\"5347bea6-8112-4ffc-bfff-375656d45106-fa567121-60f7-4c08-8957-1f7f884bb460\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}, {\"object_id\": "
      "\"5347bea6-8112-4ffc-bfff-375656d45106-f89f00e0-bf97-46c6-8540-15de8e5673c4\", \"vote\": 0, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"6e88c100-38cd-46a3-9298-894e3d01754f\", \"ballot_selections\": [{\"object_id\": "
      "\"6e88c100-38cd-46a3-9298-894e3d01754f-cdb63723-1db6-45d6-998c-ec798739800f\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"58701085-2dfa-4e96-9454-7714c2de19a2\", \"ballot_selections\": [{\"object_id\": "
      "\"58701085-2dfa-4e96-9454-7714c2de19a2-bc56f808-193c-472a-bd5f-328b9d462363\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"34e28bbf-e41a-4653-a67a-03b0c0b2e79f\", \"ballot_selections\": [{\"object_id\": "
      "\"34e28bbf-e41a-4653-a67a-03b0c0b2e79f-47a8e20d-cb61-456d-a700-2a5b58da0790\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"171373a6-492e-44c5-ad98-60b620f6c773\", \"ballot_selections\": [{\"object_id\": "
      "\"171373a6-492e-44c5-ad98-60b620f6c773-096d55a2-578e-400d-a923-46706b0a2b09\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"e80b3459-867d-4ad8-92d3-ecc5dc560fd8\", \"ballot_selections\": [{\"object_id\": "
      "\"e80b3459-867d-4ad8-92d3-ecc5dc560fd8-7a62f4e5-3322-41ed-a5ea-ddfab6d568b3\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"122c0b05-eb60-46fc-9495-507bda7fa5f9\", \"ballot_selections\": [{\"object_id\": "
      "\"122c0b05-eb60-46fc-9495-507bda7fa5f9-22456db6-5c3a-49a4-8b45-638b2dce23d6\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}, {\"object_id\": "
      "\"122c0b05-eb60-46fc-9495-507bda7fa5f9-78f5903e-f686-44aa-8d38-32e3f2d55543\", \"vote\": 0, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"3ab918aa-d3f0-4c40-9691-f7a3c18976d6\", \"ballot_selections\": [{\"object_id\": "
      "\"3ab918aa-d3f0-4c40-9691-f7a3c18976d6-036bffd8-cf8a-48a8-b87b-06a10f705e80\", \"vote\": 0, "
      "\"is_placeholder_selection\": false, \"write_in\": null}, {\"object_id\": "
      "\"3ab918aa-d3f0-4c40-9691-f7a3c18976d6-106dc350-a67d-4fb9-8484-16dcc4f9dc7e\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"c9ee9824-6704-4169-a176-32ee4b260865\", \"ballot_selections\": [{\"object_id\": "
      "\"c9ee9824-6704-4169-a176-32ee4b260865-65f197b1-1bec-4d53-b886-6bb14592582c\", \"vote\": 0, "
      "\"is_placeholder_selection\": false, \"write_in\": null}, {\"object_id\": "
      "\"c9ee9824-6704-4169-a176-32ee4b260865-847b5768-d0d7-48f9-924e-b98edb2f9b92\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"2a1c23e6-0eff-4838-9645-dbaaec8ae580\", \"ballot_selections\": [{\"object_id\": "
      "\"2a1c23e6-0eff-4838-9645-dbaaec8ae580-823efa18-9f92-4762-8067-6dd96bff5ba9\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"6d7013e6-d6fb-463e-9236-be53d17c843c\", \"ballot_selections\": [{\"object_id\": "
      "\"6d7013e6-d6fb-463e-9236-be53d17c843c-a994232b-63ba-48bb-a433-dd2d7a0c15d4\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"d118ded9-f448-41c2-8dad-4cedc61658dc\", \"ballot_selections\": [{\"object_id\": "
      "\"d118ded9-f448-41c2-8dad-4cedc61658dc-9aef2c20-6dca-4e0e-84d5-dba3c66c2f90\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"814ec976-324c-4106-8a85-90caa7b86a1f\", \"ballot_selections\": [{\"object_id\": "
      "\"814ec976-324c-4106-8a85-90caa7b86a1f-00c95845-b2d7-479a-9068-cabb90bb34bb\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"9ae1030b-6635-4168-abbb-357d56d54820\", \"ballot_selections\": [{\"object_id\": "
      "\"9ae1030b-6635-4168-abbb-357d56d54820-459bd26b-ee61-4492-b2c3-9476738774c9\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"548a6df8-099f-41a9-9e21-fec30e00b228\", \"ballot_selections\": [{\"object_id\": "
      "\"548a6df8-099f-41a9-9e21-fec30e00b228-766447c0-977e-4ab7-b060-cfab76044725\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"a479a090-58f2-40c0-91d9-7c86040aa434\", \"ballot_selections\": [{\"object_id\": "
      "\"a479a090-58f2-40c0-91d9-7c86040aa434-a5f05a39-2e2a-41b1-8001-dfd49c374842\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"283805b1-f438-44a1-84d4-41a480020084\", \"ballot_selections\": [{\"object_id\": "
      "\"283805b1-f438-44a1-84d4-41a480020084-54a1bf6e-ac88-45d8-92ef-76a102af4105\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"6a5f9bb9-e21a-419c-b672-523bfb653c7b\", \"ballot_selections\": [{\"object_id\": "
      "\"6a5f9bb9-e21a-419c-b672-523bfb653c7b-889194d1-d759-4c66-a4cd-34aa1ae4a7a0\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"0d230c4c-f9fa-4708-8df6-5f2f0c5e4118\", \"ballot_selections\": [{\"object_id\": "
      "\"0d230c4c-f9fa-4708-8df6-5f2f0c5e4118-0fc17a46-a046-40bd-8d14-22ec6cf58d16\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"c0a61c0e-d6b9-437e-bcac-a2c4c63d98be\", \"ballot_selections\": [{\"object_id\": "
      "\"c0a61c0e-d6b9-437e-bcac-a2c4c63d98be-d41899b1-4a1d-4bb2-8385-e1d5b08bc67a\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"e171eedc-026c-4e23-a972-287b8ff2639d\", \"ballot_selections\": [{\"object_id\": "
      "\"e171eedc-026c-4e23-a972-287b8ff2639d-8979f102-f5c6-4fca-a85d-a254edb1959a\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"38aafc92-3a90-4398-8c08-3132e381dcae\", \"ballot_selections\": [{\"object_id\": "
      "\"38aafc92-3a90-4398-8c08-3132e381dcae-4f3b770b-aaa0-474b-beba-61c6e8c892ea\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"a7446e5b-e2c7-4feb-8f6a-913954110d2d\", \"ballot_selections\": [{\"object_id\": "
      "\"a7446e5b-e2c7-4feb-8f6a-913954110d2d-bc47421d-20fe-47e0-8b39-42f808a23d3f\", \"vote\": 0, "
      "\"is_placeholder_selection\": false, \"write_in\": null}, {\"object_id\": "
      "\"a7446e5b-e2c7-4feb-8f6a-913954110d2d-e2d96a91-0ab3-462a-9f8a-d0ef5de18fe2\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"3d47bc4a-17d6-4cd3-a776-8d1bca8340be\", \"ballot_selections\": [{\"object_id\": "
      "\"3d47bc4a-17d6-4cd3-a776-8d1bca8340be-f1657af2-0eba-4350-a3ec-66e244c7a688\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"604468ab-b05d-4fc9-9a75-8950478f12bd\", \"ballot_selections\": [{\"object_id\": "
      "\"604468ab-b05d-4fc9-9a75-8950478f12bd-e923cb22-927e-4b9d-b8ea-feae99fe7757\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"69346544-71d2-44b9-afed-909b0063fa99\", \"ballot_selections\": [{\"object_id\": "
      "\"69346544-71d2-44b9-afed-909b0063fa99-f7e19e93-5d83-4360-a3d3-dcfa3701f7ec\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"4184c688-b114-4d51-aaa0-5ff56c340a42\", \"ballot_selections\": [{\"object_id\": "
      "\"4184c688-b114-4d51-aaa0-5ff56c340a42-3e7df895-8f69-4683-b1a7-54e1d4ee8b04\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"6cff94ed-274e-4617-90ed-927176dec47e\", \"ballot_selections\": [{\"object_id\": "
      "\"6cff94ed-274e-4617-90ed-927176dec47e-a6225126-f7c7-449f-9f8f-cad3da5a8730\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"6a2971c0-7ea9-4701-a930-993c264a8fa3\", \"ballot_selections\": [{\"object_id\": "
      "\"6a2971c0-7ea9-4701-a930-993c264a8fa3-23e2f381-4dc2-45d5-87b5-994c5702ac6c\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"f46a062b-5efe-4c2e-8e83-9db67cc35d2c\", \"ballot_selections\": [{\"object_id\": "
      "\"f46a062b-5efe-4c2e-8e83-9db67cc35d2c-972c8b84-2150-4be1-8578-446736e9d1b3\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"59ccdf94-dd02-4c85-bf26-826e9719bbe3\", \"ballot_selections\": [{\"object_id\": "
      "\"59ccdf94-dd02-4c85-bf26-826e9719bbe3-5b131fef-e731-47ff-b626-adffa3455ae9\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}, {\"object_id\": "
      "\"bb85a631-995b-4ee5-8da9-f198b2a12d4d\", \"ballot_selections\": [{\"object_id\": "
      "\"bb85a631-995b-4ee5-8da9-f198b2a12d4d-daec27c7-c8d8-4dfb-b640-dde05b056b02\", \"vote\": 1, "
      "\"is_placeholder_selection\": false, \"write_in\": null}]}]}";

    auto manifestData =
      "{\"election_scope_id\": \"1032e97c-c0c0-4609-977b-c370127b41cc\", \"spec_version\": "
      "\"1.0\", \"type\": \"general\", \"start_date\": \"2022-11-08T06:00:00+00:00\", "
      "\"end_date\": \"2022-11-09T06:00:00+00:00\", \"geopolitical_units\": [{\"object_id\": "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"name\": \"Legislative District #30\", \"type\": "
      "\"county\", \"contact_information\": null}, {\"object_id\": "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"name\": \"District 1\", \"type\": \"county\", "
      "\"contact_information\": null}, {\"object_id\": \"640341e8-2e2e-4c1f-937a-2f07f5989480\", "
      "\"name\": \"Legislative District #29\", \"type\": \"county\", \"contact_information\": "
      "null}, {\"object_id\": \"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"name\": \"Legislative "
      "District #28\", \"type\": \"county\", \"contact_information\": null}, {\"object_id\": "
      "\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"name\": \"Legislative District #32\", \"type\": "
      "\"county\", \"contact_information\": null}, {\"object_id\": "
      "\"ad915207-1f20-4bec-a63d-481cea7c362b\", \"name\": \"Federal\", \"type\": \"county\", "
      "\"contact_information\": null}, {\"object_id\": \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"name\": \"County\", \"type\": \"county\", \"contact_information\": null}, {\"object_id\": "
      "\"3ed629ac-70e2-4972-96b0-9791bbe0234c\", \"name\": \"Legislative District #27\", \"type\": "
      "\"county\", \"contact_information\": null}, {\"object_id\": "
      "\"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", \"name\": \"State\", \"type\": \"county\", "
      "\"contact_information\": null}, {\"object_id\": \"968dd0d8-472a-4358-aa20-a530921295ee\", "
      "\"name\": \"District 3\", \"type\": \"county\", \"contact_information\": null}, "
      "{\"object_id\": \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", \"name\": \"Legislative District "
      "#31\", \"type\": \"county\", \"contact_information\": null}, {\"object_id\": "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"name\": \"District 2\", \"type\": \"county\", "
      "\"contact_information\": null}, {\"object_id\": \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"name\": \"Legislative District #26\", \"type\": \"county\", \"contact_information\": "
      "null}], \"parties\": [{\"object_id\": \"6c40fdde-4979-4746-9448-e515fc950d6d\", \"name\": "
      "{\"text\": [{\"value\": \"Republican Party\", \"language\": \"en\"}]}, \"abbreviation\": "
      "\"REP\", \"color\": null, \"logo_uri\": null}, {\"object_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"name\": {\"text\": [{\"value\": \"Democratic "
      "Party\", \"language\": \"en\"}]}, \"abbreviation\": \"DEM\", \"color\": null, \"logo_uri\": "
      "null}, {\"object_id\": \"e2c3f0d6-5dde-4990-8335-7944502e097b\", \"name\": {\"text\": "
      "[{\"value\": \"Independent Party\", \"language\": \"en\"}]}, \"abbreviation\": \"IND\", "
      "\"color\": null, \"logo_uri\": null}, {\"object_id\": "
      "\"091cb50c-e8c8-4de6-bbe2-ca17e499e900\", \"name\": {\"text\": [{\"value\": \"Libertarian "
      "Party\", \"language\": \"en\"}]}, \"abbreviation\": \"LIB\", \"color\": null, \"logo_uri\": "
      "null}, {\"object_id\": \"60418076-f2d3-433a-8901-0cc42dc45a8d\", \"name\": {\"text\": "
      "[{\"value\": \"Conservative Party\", \"language\": \"en\"}]}, \"abbreviation\": \"CON\", "
      "\"color\": null, \"logo_uri\": null}], \"candidates\": [{\"object_id\": "
      "\"47a8e20d-cb61-456d-a700-2a5b58da0790\", \"name\": {\"text\": [{\"value\": \"Julie A. "
      "Ellsworth\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"decd6a10-35f0-449e-bc88-d3511dc19dfb\", \"name\": {\"text\": [{\"value\": "
      "\"Jill L Ellsworth\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"016dd1a3-9099-4359-93bd-2e197d4ec424\", \"name\": {\"text\": [{\"value\": "
      "\"Mike Simpson\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"997c30fa-5e7f-46c5-ba2c-b974d099db1a\", \"name\": {\"text\": [{\"value\": "
      "\"Wendy Norman\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"e146712d-0278-472b-a20a-986cd64a0e61\", \"name\": {\"text\": [{\"value\": "
      "\"Julianne Young\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"8979f102-f5c6-4fca-a85d-a254edb1959a\", \"name\": {\"text\": [{\"value\": "
      "\"Travis Oler\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"4f3b770b-aaa0-474b-beba-61c6e8c892ea\", \"name\": {\"text\": [{\"value\": "
      "\"Van Burtenshaw\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"65f197b1-1bec-4d53-b886-6bb14592582c\", \"name\": {\"text\": [{\"value\": "
      "\"Karma Metzler Fitzgerald\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"847b5768-d0d7-48f9-924e-b98edb2f9b92\", \"name\": {\"text\": [{\"value\": "
      "\"Jack Nelsen\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"459bd26b-ee61-4492-b2c3-9476738774c9\", \"name\": {\"text\": [{\"value\": "
      "\"Richard 'Rick' Cheatum\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"f89f00e0-bf97-46c6-8540-15de8e5673c4\", \"name\": {\"text\": [{\"value\": "
      "\"Pro-Life\", \"language\": \"en\"}]}, \"party_id\": "
      "\"60418076-f2d3-433a-8901-0cc42dc45a8d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"fa567121-60f7-4c08-8957-1f7f884bb460\", \"name\": {\"text\": [{\"value\": "
      "\"Terri Pickens Manweiler\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"9632fc7b-86b0-4b8a-ada7-c34d4f2e56f9\", \"name\": {\"text\": [{\"value\": "
      "\"Scott Bedke\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"54a1bf6e-ac88-45d8-92ef-76a102af4105\", \"name\": {\"text\": [{\"value\": "
      "\"Dustin Whitney Manwaring\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"2660f7eb-13be-4efc-b005-fe1ff38ac57c\", \"name\": {\"text\": [{\"value\": "
      "\"Mary Shea\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"9aef2c20-6dca-4e0e-84d5-dba3c66c2f90\", \"name\": {\"text\": [{\"value\": "
      "\"Clay Handy\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"78f5903e-f686-44aa-8d38-32e3f2d55543\", \"name\": {\"text\": [{\"value\": "
      "\"Donald Lappin\", \"language\": \"en\"}]}, \"party_id\": "
      "\"e2c3f0d6-5dde-4990-8335-7944502e097b\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"22456db6-5c3a-49a4-8b45-638b2dce23d6\", \"name\": {\"text\": [{\"value\": "
      "\"Ron C. Taylor\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"86104087-9ddf-4fee-b107-7fcc492661a9\", \"name\": {\"text\": [{\"value\": "
      "\"Laurie Lickley\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"889194d1-d759-4c66-a4cd-34aa1ae4a7a0\", \"name\": {\"text\": [{\"value\": "
      "\"Jake Stevens\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"49fe305e-c594-43a6-a45c-371205ac04e6\", \"name\": {\"text\": [{\"value\": "
      "\"Nate Roberts\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"0fc17a46-a046-40bd-8d14-22ec6cf58d16\", \"name\": {\"text\": [{\"value\": "
      "\"Dave Archuleta\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"4eb6e8a5-a067-4169-8831-8d76a453073c\", \"name\": {\"text\": [{\"value\": "
      "\"Julie VanOrden\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"3e7df895-8f69-4683-b1a7-54e1d4ee8b04\", \"name\": {\"text\": [{\"value\": "
      "\"Robert Dirk Bowles\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"096d55a2-578e-400d-a923-46706b0a2b09\", \"name\": {\"text\": [{\"value\": "
      "\"Steven Scanlin\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"ccef1679-ce10-48e4-aa51-fd3aad913ce8\", \"name\": {\"text\": [{\"value\": "
      "\"Raul R. Labrador\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"bc56f808-193c-472a-bd5f-328b9d462363\", \"name\": {\"text\": [{\"value\": "
      "\"Dianna David\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"8b0026cb-6e18-4d4a-8264-374c2b55e79f\", \"name\": {\"text\": [{\"value\": "
      "\"Miste Gardner\", \"language\": \"en\"}]}, \"party_id\": "
      "\"60418076-f2d3-433a-8901-0cc42dc45a8d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"0588bd36-0998-4431-ba74-c519e668bf45\", \"name\": {\"text\": [{\"value\": "
      "\"Brandon D Woolf\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"a2216393-59c2-4a50-8e00-a3d9a4d93d8d\", \"name\": {\"text\": [{\"value\": "
      "\"James D. Ruchti\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"a5f05a39-2e2a-41b1-8001-dfd49c374842\", \"name\": {\"text\": [{\"value\": "
      "\"David T. Worley\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"5b131fef-e731-47ff-b626-adffa3455ae9\", \"name\": {\"text\": [{\"value\": "
      "\"Ron H. Smellie\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"e51909c3-a56c-4065-8439-dc814f7600ef\", \"name\": {\"text\": [{\"value\": "
      "\"Phil McGrane\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"cdb63723-1db6-45d6-998c-ec798739800f\", \"name\": {\"text\": [{\"value\": "
      "\"Shawn Keenan\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"e923cb22-927e-4b9d-b8ea-feae99fe7757\", \"name\": {\"text\": [{\"value\": "
      "\"Kevin Cook\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"f1657af2-0eba-4350-a3ec-66e244c7a688\", \"name\": {\"text\": [{\"value\": "
      "\"Wayne Talmadge\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"01f2f0d1-27d6-4a78-8a9d-98df88d31cba\", \"name\": {\"text\": [{\"value\": "
      "\"Rod Furniss\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"f7e19e93-5d83-4360-a3d3-dcfa3701f7ec\", \"name\": {\"text\": [{\"value\": "
      "\"Robert C. Swainton\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"7c949291-a9db-4569-bf30-036a6f098fbf\", \"name\": {\"text\": [{\"value\": "
      "\"Mike Saville\", \"language\": \"en\"}]}, \"party_id\": "
      "\"e2c3f0d6-5dde-4990-8335-7944502e097b\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"00c95845-b2d7-479a-9068-cabb90bb34bb\", \"name\": {\"text\": [{\"value\": "
      "\"Jim Guthrie\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"bc47421d-20fe-47e0-8b39-42f808a23d3f\", \"name\": {\"text\": [{\"value\": "
      "\"Jerald Raymond\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"e2d96a91-0ab3-462a-9f8a-d0ef5de18fe2\", \"name\": {\"text\": [{\"value\": "
      "\"Connie Delaney\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"a6225126-f7c7-449f-9f8f-cad3da5a8730\", \"name\": {\"text\": [{\"value\": "
      "\"Camille Larsen\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"23e2f381-4dc2-45d5-87b5-994c5702ac6c\", \"name\": {\"text\": [{\"value\": "
      "\"Janet Kimpton\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"972c8b84-2150-4be1-8578-446736e9d1b3\", \"name\": {\"text\": [{\"value\": "
      "\"Chris Barton\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"8902f19c-0802-42d8-a532-23fa5a95bc43\", \"name\": {\"text\": [{\"value\": "
      "\"Chantyrose Davison\", \"language\": \"en\"}]}, \"party_id\": "
      "\"60418076-f2d3-433a-8901-0cc42dc45a8d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"81b8380b-8a44-497c-a9c8-83fe8258670e\", \"name\": {\"text\": [{\"value\": "
      "\"Brad Little\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"f19cf844-d851-4ff0-bc50-a7d79a5c1f0c\", \"name\": {\"text\": [{\"value\": "
      "\"Ammon Bundy\", \"language\": \"en\"}]}, \"party_id\": "
      "\"e2c3f0d6-5dde-4990-8335-7944502e097b\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"fd1cdb20-efed-441c-bd1a-a84e9e92d175\", \"name\": {\"text\": [{\"value\": "
      "\"Paul Sand\", \"language\": \"en\"}]}, \"party_id\": "
      "\"091cb50c-e8c8-4de6-bbe2-ca17e499e900\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"47179eb7-d042-44d8-aed7-e8011087c591\", \"name\": {\"text\": [{\"value\": "
      "\"Stephen Heidt\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"14fd1fe4-c801-4d69-b58a-cc8d806835c2\", \"name\": {\"text\": [{\"value\": "
      "\"Russ Fulcher\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"c45e78aa-a605-4777-8339-fd7983894262\", \"name\": {\"text\": [{\"value\": "
      "\"Joe Evans\", \"language\": \"en\"}]}, \"party_id\": "
      "\"091cb50c-e8c8-4de6-bbe2-ca17e499e900\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"5684632f-e4e9-4ce4-bddc-ff83e7835511\", \"name\": {\"text\": [{\"value\": "
      "\"Kaylee Peterson\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"d41899b1-4a1d-4bb2-8385-e1d5b08bc67a\", \"name\": {\"text\": [{\"value\": "
      "\"David Cannon\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"a994232b-63ba-48bb-a433-dd2d7a0c15d4\", \"name\": {\"text\": [{\"value\": "
      "\"Douglas T Pickett\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"823efa18-9f92-4762-8067-6dd96bff5ba9\", \"name\": {\"text\": [{\"value\": "
      "\"Bill Drury\", \"language\": \"en\"}]}, \"party_id\": "
      "\"e2c3f0d6-5dde-4990-8335-7944502e097b\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"c08f564f-e95e-4d80-9601-9588775d86f8\", \"name\": {\"text\": [{\"value\": "
      "\"Kelly Anthon\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"cb33e666-e93f-4b8e-a161-45d14539b58f\", \"name\": {\"text\": [{\"value\": "
      "\"Debbie Critchfield\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"7a62f4e5-3322-41ed-a5ea-ddfab6d568b3\", \"name\": {\"text\": [{\"value\": "
      "\"Terry L. Gilbert\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"daec27c7-c8d8-4dfb-b640-dde05b056b02\", \"name\": {\"text\": [{\"value\": "
      "\"\", \"language\": \"en\"}]}, \"party_id\": null, \"image_uri\": null, \"is_write_in\": "
      "true}, {\"object_id\": \"036bffd8-cf8a-48a8-b87b-06a10f705e80\", \"name\": {\"text\": "
      "[{\"value\": \"Ned Burns\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"106dc350-a67d-4fb9-8484-16dcc4f9dc7e\", \"name\": {\"text\": [{\"value\": "
      "\"Mike Pohanka\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"fba8335b-175a-4864-ac0f-29d7e9cb8989\", \"name\": {\"text\": [{\"value\": "
      "\"Ray J. Writz\", \"language\": \"en\"}]}, \"party_id\": "
      "\"60418076-f2d3-433a-8901-0cc42dc45a8d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"c9be49a1-1060-4318-935f-344fa96901c7\", \"name\": {\"text\": [{\"value\": "
      "\"Idaho Sierra Law\", \"language\": \"en\"}]}, \"party_id\": "
      "\"091cb50c-e8c8-4de6-bbe2-ca17e499e900\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"50079231-f9d8-4ad6-bdaa-42a2a9d66446\", \"name\": {\"text\": [{\"value\": "
      "\"\", \"language\": \"en\"}]}, \"party_id\": null, \"image_uri\": null, \"is_write_in\": "
      "true}, {\"object_id\": \"d7e80977-acc2-4433-ad07-cc4b4b23a7c9\", \"name\": {\"text\": "
      "[{\"value\": \"Scott OH Cleveland\", \"language\": \"en\"}]}, \"party_id\": "
      "\"e2c3f0d6-5dde-4990-8335-7944502e097b\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"5cf0794a-22ba-42c3-90d4-d23df7e221c1\", \"name\": {\"text\": [{\"value\": "
      "\"Mike Crapo\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"8a3a7be9-fc51-4b50-b845-de268d268c0e\", \"name\": {\"text\": [{\"value\": "
      "\"David Roth\", \"language\": \"en\"}]}, \"party_id\": "
      "\"0f3aada6-c652-429c-9a41-d6ddf7f6f80f\", \"image_uri\": null, \"is_write_in\": null}, "
      "{\"object_id\": \"766447c0-977e-4ab7-b060-cfab76044725\", \"name\": {\"text\": [{\"value\": "
      "\"Dan Garner\", \"language\": \"en\"}]}, \"party_id\": "
      "\"6c40fdde-4979-4746-9448-e515fc950d6d\", \"image_uri\": null, \"is_write_in\": null}], "
      "\"contests\": [{\"object_id\": \"9e5ca147-8f8a-414c-86c9-fa3b6c45754b\", "
      "\"sequence_order\": 1, \"electoral_district_id\": \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"vote_variation\": \"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": "
      "\"United States Senator\", \"ballot_selections\": [{\"object_id\": "
      "\"9e5ca147-8f8a-414c-86c9-fa3b6c45754b-d7e80977-acc2-4433-ad07-cc4b4b23a7c9\", "
      "\"sequence_order\": 1, \"candidate_id\": \"d7e80977-acc2-4433-ad07-cc4b4b23a7c9\"}, "
      "{\"object_id\": "
      "\"9e5ca147-8f8a-414c-86c9-fa3b6c45754b-5cf0794a-22ba-42c3-90d4-d23df7e221c1\", "
      "\"sequence_order\": 2, \"candidate_id\": \"5cf0794a-22ba-42c3-90d4-d23df7e221c1\"}, "
      "{\"object_id\": "
      "\"9e5ca147-8f8a-414c-86c9-fa3b6c45754b-8a3a7be9-fc51-4b50-b845-de268d268c0e\", "
      "\"sequence_order\": 3, \"candidate_id\": \"8a3a7be9-fc51-4b50-b845-de268d268c0e\"}, "
      "{\"object_id\": "
      "\"9e5ca147-8f8a-414c-86c9-fa3b6c45754b-c9be49a1-1060-4318-935f-344fa96901c7\", "
      "\"sequence_order\": 4, \"candidate_id\": \"c9be49a1-1060-4318-935f-344fa96901c7\"}, "
      "{\"object_id\": "
      "\"9e5ca147-8f8a-414c-86c9-fa3b6c45754b-fba8335b-175a-4864-ac0f-29d7e9cb8989\", "
      "\"sequence_order\": 5, \"candidate_id\": \"fba8335b-175a-4864-ac0f-29d7e9cb8989\"}, "
      "{\"object_id\": "
      "\"9e5ca147-8f8a-414c-86c9-fa3b6c45754b-50079231-f9d8-4ad6-bdaa-42a2a9d66446\", "
      "\"sequence_order\": 6, \"candidate_id\": \"50079231-f9d8-4ad6-bdaa-42a2a9d66446\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"716043f6-3e08-43e1-9652-a2364bb3a170\", \"sequence_order\": 2, \"electoral_district_id\": "
      "\"ad915207-1f20-4bec-a63d-481cea7c362b\", \"vote_variation\": \"one_of_m\", "
      "\"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"United States Representative - "
      "District 1\", \"ballot_selections\": [{\"object_id\": "
      "\"716043f6-3e08-43e1-9652-a2364bb3a170-c45e78aa-a605-4777-8339-fd7983894262\", "
      "\"sequence_order\": 1, \"candidate_id\": \"c45e78aa-a605-4777-8339-fd7983894262\"}, "
      "{\"object_id\": "
      "\"716043f6-3e08-43e1-9652-a2364bb3a170-14fd1fe4-c801-4d69-b58a-cc8d806835c2\", "
      "\"sequence_order\": 2, \"candidate_id\": \"14fd1fe4-c801-4d69-b58a-cc8d806835c2\"}, "
      "{\"object_id\": "
      "\"716043f6-3e08-43e1-9652-a2364bb3a170-5684632f-e4e9-4ce4-bddc-ff83e7835511\", "
      "\"sequence_order\": 3, \"candidate_id\": \"5684632f-e4e9-4ce4-bddc-ff83e7835511\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"98402323-e396-4f83-bc86-266cc583781d\", \"sequence_order\": 3, \"electoral_district_id\": "
      "\"ad915207-1f20-4bec-a63d-481cea7c362b\", \"vote_variation\": \"one_of_m\", "
      "\"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"United States Representative - "
      "District 2\", \"ballot_selections\": [{\"object_id\": "
      "\"98402323-e396-4f83-bc86-266cc583781d-997c30fa-5e7f-46c5-ba2c-b974d099db1a\", "
      "\"sequence_order\": 1, \"candidate_id\": \"997c30fa-5e7f-46c5-ba2c-b974d099db1a\"}, "
      "{\"object_id\": "
      "\"98402323-e396-4f83-bc86-266cc583781d-016dd1a3-9099-4359-93bd-2e197d4ec424\", "
      "\"sequence_order\": 2, \"candidate_id\": \"016dd1a3-9099-4359-93bd-2e197d4ec424\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"a888ca92-5ae2-42b3-a342-9fb6d1a76689\", \"sequence_order\": 4, \"electoral_district_id\": "
      "\"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", \"vote_variation\": \"one_of_m\", "
      "\"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"Governor\", \"ballot_selections\": "
      "[{\"object_id\": "
      "\"a888ca92-5ae2-42b3-a342-9fb6d1a76689-f19cf844-d851-4ff0-bc50-a7d79a5c1f0c\", "
      "\"sequence_order\": 1, \"candidate_id\": \"f19cf844-d851-4ff0-bc50-a7d79a5c1f0c\"}, "
      "{\"object_id\": "
      "\"a888ca92-5ae2-42b3-a342-9fb6d1a76689-8902f19c-0802-42d8-a532-23fa5a95bc43\", "
      "\"sequence_order\": 2, \"candidate_id\": \"8902f19c-0802-42d8-a532-23fa5a95bc43\"}, "
      "{\"object_id\": "
      "\"a888ca92-5ae2-42b3-a342-9fb6d1a76689-47179eb7-d042-44d8-aed7-e8011087c591\", "
      "\"sequence_order\": 3, \"candidate_id\": \"47179eb7-d042-44d8-aed7-e8011087c591\"}, "
      "{\"object_id\": "
      "\"a888ca92-5ae2-42b3-a342-9fb6d1a76689-81b8380b-8a44-497c-a9c8-83fe8258670e\", "
      "\"sequence_order\": 4, \"candidate_id\": \"81b8380b-8a44-497c-a9c8-83fe8258670e\"}, "
      "{\"object_id\": "
      "\"a888ca92-5ae2-42b3-a342-9fb6d1a76689-fd1cdb20-efed-441c-bd1a-a84e9e92d175\", "
      "\"sequence_order\": 5, \"candidate_id\": \"fd1cdb20-efed-441c-bd1a-a84e9e92d175\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"5347bea6-8112-4ffc-bfff-375656d45106\", \"sequence_order\": 5, \"electoral_district_id\": "
      "\"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", \"vote_variation\": \"one_of_m\", "
      "\"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"Lietenant Governor\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"5347bea6-8112-4ffc-bfff-375656d45106-9632fc7b-86b0-4b8a-ada7-c34d4f2e56f9\", "
      "\"sequence_order\": 1, \"candidate_id\": \"9632fc7b-86b0-4b8a-ada7-c34d4f2e56f9\"}, "
      "{\"object_id\": "
      "\"5347bea6-8112-4ffc-bfff-375656d45106-fa567121-60f7-4c08-8957-1f7f884bb460\", "
      "\"sequence_order\": 2, \"candidate_id\": \"fa567121-60f7-4c08-8957-1f7f884bb460\"}, "
      "{\"object_id\": "
      "\"5347bea6-8112-4ffc-bfff-375656d45106-f89f00e0-bf97-46c6-8540-15de8e5673c4\", "
      "\"sequence_order\": 3, \"candidate_id\": \"f89f00e0-bf97-46c6-8540-15de8e5673c4\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"6e88c100-38cd-46a3-9298-894e3d01754f\", \"sequence_order\": 6, \"electoral_district_id\": "
      "\"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", \"vote_variation\": \"one_of_m\", "
      "\"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"Secretary of State\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"6e88c100-38cd-46a3-9298-894e3d01754f-cdb63723-1db6-45d6-998c-ec798739800f\", "
      "\"sequence_order\": 1, \"candidate_id\": \"cdb63723-1db6-45d6-998c-ec798739800f\"}, "
      "{\"object_id\": "
      "\"6e88c100-38cd-46a3-9298-894e3d01754f-e51909c3-a56c-4065-8439-dc814f7600ef\", "
      "\"sequence_order\": 2, \"candidate_id\": \"e51909c3-a56c-4065-8439-dc814f7600ef\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"58701085-2dfa-4e96-9454-7714c2de19a2\", \"sequence_order\": 7, \"electoral_district_id\": "
      "\"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", \"vote_variation\": \"one_of_m\", "
      "\"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State Controller\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"58701085-2dfa-4e96-9454-7714c2de19a2-bc56f808-193c-472a-bd5f-328b9d462363\", "
      "\"sequence_order\": 1, \"candidate_id\": \"bc56f808-193c-472a-bd5f-328b9d462363\"}, "
      "{\"object_id\": "
      "\"58701085-2dfa-4e96-9454-7714c2de19a2-8b0026cb-6e18-4d4a-8264-374c2b55e79f\", "
      "\"sequence_order\": 2, \"candidate_id\": \"8b0026cb-6e18-4d4a-8264-374c2b55e79f\"}, "
      "{\"object_id\": "
      "\"58701085-2dfa-4e96-9454-7714c2de19a2-0588bd36-0998-4431-ba74-c519e668bf45\", "
      "\"sequence_order\": 3, \"candidate_id\": \"0588bd36-0998-4431-ba74-c519e668bf45\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"34e28bbf-e41a-4653-a67a-03b0c0b2e79f\", \"sequence_order\": 8, \"electoral_district_id\": "
      "\"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", \"vote_variation\": \"one_of_m\", "
      "\"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State Treasurer\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"34e28bbf-e41a-4653-a67a-03b0c0b2e79f-decd6a10-35f0-449e-bc88-d3511dc19dfb\", "
      "\"sequence_order\": 1, \"candidate_id\": \"decd6a10-35f0-449e-bc88-d3511dc19dfb\"}, "
      "{\"object_id\": "
      "\"34e28bbf-e41a-4653-a67a-03b0c0b2e79f-47a8e20d-cb61-456d-a700-2a5b58da0790\", "
      "\"sequence_order\": 2, \"candidate_id\": \"47a8e20d-cb61-456d-a700-2a5b58da0790\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"171373a6-492e-44c5-ad98-60b620f6c773\", \"sequence_order\": 9, \"electoral_district_id\": "
      "\"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", \"vote_variation\": \"one_of_m\", "
      "\"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"Attorney General\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"171373a6-492e-44c5-ad98-60b620f6c773-ccef1679-ce10-48e4-aa51-fd3aad913ce8\", "
      "\"sequence_order\": 1, \"candidate_id\": \"ccef1679-ce10-48e4-aa51-fd3aad913ce8\"}, "
      "{\"object_id\": "
      "\"171373a6-492e-44c5-ad98-60b620f6c773-096d55a2-578e-400d-a923-46706b0a2b09\", "
      "\"sequence_order\": 2, \"candidate_id\": \"096d55a2-578e-400d-a923-46706b0a2b09\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"e80b3459-867d-4ad8-92d3-ecc5dc560fd8\", \"sequence_order\": 10, "
      "\"electoral_district_id\": \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"Superintendent of "
      "Publilc Instruction\", \"ballot_selections\": [{\"object_id\": "
      "\"e80b3459-867d-4ad8-92d3-ecc5dc560fd8-cb33e666-e93f-4b8e-a161-45d14539b58f\", "
      "\"sequence_order\": 1, \"candidate_id\": \"cb33e666-e93f-4b8e-a161-45d14539b58f\"}, "
      "{\"object_id\": "
      "\"e80b3459-867d-4ad8-92d3-ecc5dc560fd8-7a62f4e5-3322-41ed-a5ea-ddfab6d568b3\", "
      "\"sequence_order\": 2, \"candidate_id\": \"7a62f4e5-3322-41ed-a5ea-ddfab6d568b3\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"122c0b05-eb60-46fc-9495-507bda7fa5f9\", \"sequence_order\": 11, "
      "\"electoral_district_id\": \"9ac36694-4cce-44be-801b-d5229b1729fd\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State Senator\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"122c0b05-eb60-46fc-9495-507bda7fa5f9-78f5903e-f686-44aa-8d38-32e3f2d55543\", "
      "\"sequence_order\": 1, \"candidate_id\": \"78f5903e-f686-44aa-8d38-32e3f2d55543\"}, "
      "{\"object_id\": "
      "\"122c0b05-eb60-46fc-9495-507bda7fa5f9-86104087-9ddf-4fee-b107-7fcc492661a9\", "
      "\"sequence_order\": 2, \"candidate_id\": \"86104087-9ddf-4fee-b107-7fcc492661a9\"}, "
      "{\"object_id\": "
      "\"122c0b05-eb60-46fc-9495-507bda7fa5f9-22456db6-5c3a-49a4-8b45-638b2dce23d6\", "
      "\"sequence_order\": 3, \"candidate_id\": \"22456db6-5c3a-49a4-8b45-638b2dce23d6\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"3ab918aa-d3f0-4c40-9691-f7a3c18976d6\", \"sequence_order\": 12, "
      "\"electoral_district_id\": \"9ac36694-4cce-44be-801b-d5229b1729fd\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State "
      "Representative, Position A\", \"ballot_selections\": [{\"object_id\": "
      "\"3ab918aa-d3f0-4c40-9691-f7a3c18976d6-036bffd8-cf8a-48a8-b87b-06a10f705e80\", "
      "\"sequence_order\": 1, \"candidate_id\": \"036bffd8-cf8a-48a8-b87b-06a10f705e80\"}, "
      "{\"object_id\": "
      "\"3ab918aa-d3f0-4c40-9691-f7a3c18976d6-106dc350-a67d-4fb9-8484-16dcc4f9dc7e\", "
      "\"sequence_order\": 2, \"candidate_id\": \"106dc350-a67d-4fb9-8484-16dcc4f9dc7e\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"c9ee9824-6704-4169-a176-32ee4b260865\", \"sequence_order\": 13, "
      "\"electoral_district_id\": \"9ac36694-4cce-44be-801b-d5229b1729fd\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State "
      "Representative, Position B\", \"ballot_selections\": [{\"object_id\": "
      "\"c9ee9824-6704-4169-a176-32ee4b260865-65f197b1-1bec-4d53-b886-6bb14592582c\", "
      "\"sequence_order\": 1, \"candidate_id\": \"65f197b1-1bec-4d53-b886-6bb14592582c\"}, "
      "{\"object_id\": "
      "\"c9ee9824-6704-4169-a176-32ee4b260865-847b5768-d0d7-48f9-924e-b98edb2f9b92\", "
      "\"sequence_order\": 2, \"candidate_id\": \"847b5768-d0d7-48f9-924e-b98edb2f9b92\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"2a1c23e6-0eff-4838-9645-dbaaec8ae580\", \"sequence_order\": 14, "
      "\"electoral_district_id\": \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State Senator\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"2a1c23e6-0eff-4838-9645-dbaaec8ae580-c08f564f-e95e-4d80-9601-9588775d86f8\", "
      "\"sequence_order\": 1, \"candidate_id\": \"c08f564f-e95e-4d80-9601-9588775d86f8\"}, "
      "{\"object_id\": "
      "\"2a1c23e6-0eff-4838-9645-dbaaec8ae580-823efa18-9f92-4762-8067-6dd96bff5ba9\", "
      "\"sequence_order\": 2, \"candidate_id\": \"823efa18-9f92-4762-8067-6dd96bff5ba9\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"6d7013e6-d6fb-463e-9236-be53d17c843c\", \"sequence_order\": 15, "
      "\"electoral_district_id\": \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State "
      "Representative, Position A\", \"ballot_selections\": [{\"object_id\": "
      "\"6d7013e6-d6fb-463e-9236-be53d17c843c-a994232b-63ba-48bb-a433-dd2d7a0c15d4\", "
      "\"sequence_order\": 1, \"candidate_id\": \"a994232b-63ba-48bb-a433-dd2d7a0c15d4\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"d118ded9-f448-41c2-8dad-4cedc61658dc\", \"sequence_order\": 16, "
      "\"electoral_district_id\": \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State "
      "Representative, Position B\", \"ballot_selections\": [{\"object_id\": "
      "\"d118ded9-f448-41c2-8dad-4cedc61658dc-9aef2c20-6dca-4e0e-84d5-dba3c66c2f90\", "
      "\"sequence_order\": 1, \"candidate_id\": \"9aef2c20-6dca-4e0e-84d5-dba3c66c2f90\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"814ec976-324c-4106-8a85-90caa7b86a1f\", \"sequence_order\": 17, "
      "\"electoral_district_id\": \"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State Senator\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"814ec976-324c-4106-8a85-90caa7b86a1f-00c95845-b2d7-479a-9068-cabb90bb34bb\", "
      "\"sequence_order\": 1, \"candidate_id\": \"00c95845-b2d7-479a-9068-cabb90bb34bb\"}, "
      "{\"object_id\": "
      "\"814ec976-324c-4106-8a85-90caa7b86a1f-7c949291-a9db-4569-bf30-036a6f098fbf\", "
      "\"sequence_order\": 2, \"candidate_id\": \"7c949291-a9db-4569-bf30-036a6f098fbf\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"9ae1030b-6635-4168-abbb-357d56d54820\", \"sequence_order\": 18, "
      "\"electoral_district_id\": \"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State "
      "Representative, Position A\", \"ballot_selections\": [{\"object_id\": "
      "\"9ae1030b-6635-4168-abbb-357d56d54820-459bd26b-ee61-4492-b2c3-9476738774c9\", "
      "\"sequence_order\": 1, \"candidate_id\": \"459bd26b-ee61-4492-b2c3-9476738774c9\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"548a6df8-099f-41a9-9e21-fec30e00b228\", \"sequence_order\": 19, "
      "\"electoral_district_id\": \"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State "
      "Representative, Position B\", \"ballot_selections\": [{\"object_id\": "
      "\"548a6df8-099f-41a9-9e21-fec30e00b228-766447c0-977e-4ab7-b060-cfab76044725\", "
      "\"sequence_order\": 1, \"candidate_id\": \"766447c0-977e-4ab7-b060-cfab76044725\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"a479a090-58f2-40c0-91d9-7c86040aa434\", \"sequence_order\": 20, "
      "\"electoral_district_id\": \"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State Senator\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"a479a090-58f2-40c0-91d9-7c86040aa434-a2216393-59c2-4a50-8e00-a3d9a4d93d8d\", "
      "\"sequence_order\": 1, \"candidate_id\": \"a2216393-59c2-4a50-8e00-a3d9a4d93d8d\"}, "
      "{\"object_id\": "
      "\"a479a090-58f2-40c0-91d9-7c86040aa434-a5f05a39-2e2a-41b1-8001-dfd49c374842\", "
      "\"sequence_order\": 2, \"candidate_id\": \"a5f05a39-2e2a-41b1-8001-dfd49c374842\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"283805b1-f438-44a1-84d4-41a480020084\", \"sequence_order\": 21, "
      "\"electoral_district_id\": \"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State "
      "Representative, Position A\", \"ballot_selections\": [{\"object_id\": "
      "\"283805b1-f438-44a1-84d4-41a480020084-54a1bf6e-ac88-45d8-92ef-76a102af4105\", "
      "\"sequence_order\": 1, \"candidate_id\": \"54a1bf6e-ac88-45d8-92ef-76a102af4105\"}, "
      "{\"object_id\": "
      "\"283805b1-f438-44a1-84d4-41a480020084-2660f7eb-13be-4efc-b005-fe1ff38ac57c\", "
      "\"sequence_order\": 2, \"candidate_id\": \"2660f7eb-13be-4efc-b005-fe1ff38ac57c\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"6a5f9bb9-e21a-419c-b672-523bfb653c7b\", \"sequence_order\": 22, "
      "\"electoral_district_id\": \"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State "
      "Representative, Position B\", \"ballot_selections\": [{\"object_id\": "
      "\"6a5f9bb9-e21a-419c-b672-523bfb653c7b-49fe305e-c594-43a6-a45c-371205ac04e6\", "
      "\"sequence_order\": 1, \"candidate_id\": \"49fe305e-c594-43a6-a45c-371205ac04e6\"}, "
      "{\"object_id\": "
      "\"6a5f9bb9-e21a-419c-b672-523bfb653c7b-889194d1-d759-4c66-a4cd-34aa1ae4a7a0\", "
      "\"sequence_order\": 2, \"candidate_id\": \"889194d1-d759-4c66-a4cd-34aa1ae4a7a0\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"0d230c4c-f9fa-4708-8df6-5f2f0c5e4118\", \"sequence_order\": 23, "
      "\"electoral_district_id\": \"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State Senator\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"0d230c4c-f9fa-4708-8df6-5f2f0c5e4118-0fc17a46-a046-40bd-8d14-22ec6cf58d16\", "
      "\"sequence_order\": 1, \"candidate_id\": \"0fc17a46-a046-40bd-8d14-22ec6cf58d16\"}, "
      "{\"object_id\": "
      "\"0d230c4c-f9fa-4708-8df6-5f2f0c5e4118-4eb6e8a5-a067-4169-8831-8d76a453073c\", "
      "\"sequence_order\": 2, \"candidate_id\": \"4eb6e8a5-a067-4169-8831-8d76a453073c\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"c0a61c0e-d6b9-437e-bcac-a2c4c63d98be\", \"sequence_order\": 24, "
      "\"electoral_district_id\": \"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State "
      "Representative, Position A\", \"ballot_selections\": [{\"object_id\": "
      "\"c0a61c0e-d6b9-437e-bcac-a2c4c63d98be-d41899b1-4a1d-4bb2-8385-e1d5b08bc67a\", "
      "\"sequence_order\": 1, \"candidate_id\": \"d41899b1-4a1d-4bb2-8385-e1d5b08bc67a\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"e171eedc-026c-4e23-a972-287b8ff2639d\", \"sequence_order\": 25, "
      "\"electoral_district_id\": \"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State "
      "Representative, Position B\", \"ballot_selections\": [{\"object_id\": "
      "\"e171eedc-026c-4e23-a972-287b8ff2639d-8979f102-f5c6-4fca-a85d-a254edb1959a\", "
      "\"sequence_order\": 1, \"candidate_id\": \"8979f102-f5c6-4fca-a85d-a254edb1959a\"}, "
      "{\"object_id\": "
      "\"e171eedc-026c-4e23-a972-287b8ff2639d-e146712d-0278-472b-a20a-986cd64a0e61\", "
      "\"sequence_order\": 2, \"candidate_id\": \"e146712d-0278-472b-a20a-986cd64a0e61\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"38aafc92-3a90-4398-8c08-3132e381dcae\", \"sequence_order\": 26, "
      "\"electoral_district_id\": \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State Senator\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"38aafc92-3a90-4398-8c08-3132e381dcae-4f3b770b-aaa0-474b-beba-61c6e8c892ea\", "
      "\"sequence_order\": 1, \"candidate_id\": \"4f3b770b-aaa0-474b-beba-61c6e8c892ea\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"a7446e5b-e2c7-4feb-8f6a-913954110d2d\", \"sequence_order\": 27, "
      "\"electoral_district_id\": \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State "
      "Representative, Position A\", \"ballot_selections\": [{\"object_id\": "
      "\"a7446e5b-e2c7-4feb-8f6a-913954110d2d-e2d96a91-0ab3-462a-9f8a-d0ef5de18fe2\", "
      "\"sequence_order\": 1, \"candidate_id\": \"e2d96a91-0ab3-462a-9f8a-d0ef5de18fe2\"}, "
      "{\"object_id\": "
      "\"a7446e5b-e2c7-4feb-8f6a-913954110d2d-bc47421d-20fe-47e0-8b39-42f808a23d3f\", "
      "\"sequence_order\": 2, \"candidate_id\": \"bc47421d-20fe-47e0-8b39-42f808a23d3f\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"3d47bc4a-17d6-4cd3-a776-8d1bca8340be\", \"sequence_order\": 28, "
      "\"electoral_district_id\": \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State "
      "Representative, Position B\", \"ballot_selections\": [{\"object_id\": "
      "\"3d47bc4a-17d6-4cd3-a776-8d1bca8340be-01f2f0d1-27d6-4a78-8a9d-98df88d31cba\", "
      "\"sequence_order\": 1, \"candidate_id\": \"01f2f0d1-27d6-4a78-8a9d-98df88d31cba\"}, "
      "{\"object_id\": "
      "\"3d47bc4a-17d6-4cd3-a776-8d1bca8340be-f1657af2-0eba-4350-a3ec-66e244c7a688\", "
      "\"sequence_order\": 2, \"candidate_id\": \"f1657af2-0eba-4350-a3ec-66e244c7a688\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"604468ab-b05d-4fc9-9a75-8950478f12bd\", \"sequence_order\": 29, "
      "\"electoral_district_id\": \"63ce95a3-88a1-4639-90df-42d66332fa90\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"State Senator\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"604468ab-b05d-4fc9-9a75-8950478f12bd-e923cb22-927e-4b9d-b8ea-feae99fe7757\", "
      "\"sequence_order\": 1, \"candidate_id\": \"e923cb22-927e-4b9d-b8ea-feae99fe7757\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"69346544-71d2-44b9-afed-909b0063fa99\", \"sequence_order\": 30, "
      "\"electoral_district_id\": \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"County Commissioner "
      "District#2\", \"ballot_selections\": [{\"object_id\": "
      "\"69346544-71d2-44b9-afed-909b0063fa99-f7e19e93-5d83-4360-a3d3-dcfa3701f7ec\", "
      "\"sequence_order\": 1, \"candidate_id\": \"f7e19e93-5d83-4360-a3d3-dcfa3701f7ec\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"4184c688-b114-4d51-aaa0-5ff56c340a42\", \"sequence_order\": 31, "
      "\"electoral_district_id\": \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"County Commissioner "
      "District#3\", \"ballot_selections\": [{\"object_id\": "
      "\"4184c688-b114-4d51-aaa0-5ff56c340a42-3e7df895-8f69-4683-b1a7-54e1d4ee8b04\", "
      "\"sequence_order\": 1, \"candidate_id\": \"3e7df895-8f69-4683-b1a7-54e1d4ee8b04\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"6cff94ed-274e-4617-90ed-927176dec47e\", \"sequence_order\": 32, "
      "\"electoral_district_id\": \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"Clerk of District "
      "Court\", \"ballot_selections\": [{\"object_id\": "
      "\"6cff94ed-274e-4617-90ed-927176dec47e-a6225126-f7c7-449f-9f8f-cad3da5a8730\", "
      "\"sequence_order\": 1, \"candidate_id\": \"a6225126-f7c7-449f-9f8f-cad3da5a8730\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"6a2971c0-7ea9-4701-a930-993c264a8fa3\", \"sequence_order\": 33, "
      "\"electoral_district_id\": \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"County Treasurer\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"6a2971c0-7ea9-4701-a930-993c264a8fa3-23e2f381-4dc2-45d5-87b5-994c5702ac6c\", "
      "\"sequence_order\": 1, \"candidate_id\": \"23e2f381-4dc2-45d5-87b5-994c5702ac6c\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"f46a062b-5efe-4c2e-8e83-9db67cc35d2c\", \"sequence_order\": 34, "
      "\"electoral_district_id\": \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"County Assessor\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"f46a062b-5efe-4c2e-8e83-9db67cc35d2c-972c8b84-2150-4be1-8578-446736e9d1b3\", "
      "\"sequence_order\": 1, \"candidate_id\": \"972c8b84-2150-4be1-8578-446736e9d1b3\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"59ccdf94-dd02-4c85-bf26-826e9719bbe3\", \"sequence_order\": 35, "
      "\"electoral_district_id\": \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"County Coroner\", "
      "\"ballot_selections\": [{\"object_id\": "
      "\"59ccdf94-dd02-4c85-bf26-826e9719bbe3-5b131fef-e731-47ff-b626-adffa3455ae9\", "
      "\"sequence_order\": 1, \"candidate_id\": \"5b131fef-e731-47ff-b626-adffa3455ae9\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}, {\"object_id\": "
      "\"bb85a631-995b-4ee5-8da9-f198b2a12d4d\", \"sequence_order\": 36, "
      "\"electoral_district_id\": \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", \"vote_variation\": "
      "\"one_of_m\", \"number_elected\": 1, \"votes_allowed\": 1, \"name\": \"Franklin County Soil "
      "and Conservation District Supervisors\", \"ballot_selections\": [{\"object_id\": "
      "\"bb85a631-995b-4ee5-8da9-f198b2a12d4d-daec27c7-c8d8-4dfb-b640-dde05b056b02\", "
      "\"sequence_order\": 1, \"candidate_id\": \"daec27c7-c8d8-4dfb-b640-dde05b056b02\"}], "
      "\"ballot_title\": null, \"ballot_subtitle\": null}], \"ballot_styles\": [{\"object_id\": "
      "\"c289f114-6170-4313-b0c3-098fb0d9bacc\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"c39d37d9-b734-4fb5-9540-3571237b9698\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"e3505391-aca6-4666-aadf-4fb31357170b\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"44015ed0-21f9-4b4c-9249-524f48af66a5\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"6fb51ce4-fa55-474f-b54c-5612753f1de5\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"feae2c1d-3051-4e44-b58e-6e13e85175ff\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"9fcc3daf-0d63-4c6f-b2b9-6e306eb13fbe\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"e8736bd4-7c2e-4a86-9f7e-7f3a23f39e7f\", \"geopolitical_unit_ids\": "
      "[\"968dd0d8-472a-4358-aa20-a530921295ee\", \"63ce95a3-88a1-4639-90df-42d66332fa90\", "
      "\"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", \"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", "
      "\"9ac36694-4cce-44be-801b-d5229b1729fd\", \"8a3ee3cc-b079-47eb-83bd-234e84f73176\", "
      "\"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", \"912e4633-6494-4bda-becd-b7e4cc888e24\", "
      "\"ad915207-1f20-4bec-a63d-481cea7c362b\", \"640341e8-2e2e-4c1f-937a-2f07f5989480\", "
      "\"3ed629ac-70e2-4972-96b0-9791bbe0234c\", \"8b7fa555-5114-491f-8c1b-1068a306bb0d\", "
      "\"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"da68ca8e-e876-417d-a09e-91f2aa0c4dd5\", \"geopolitical_unit_ids\": "
      "[\"968dd0d8-472a-4358-aa20-a530921295ee\", \"63ce95a3-88a1-4639-90df-42d66332fa90\", "
      "\"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", \"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", "
      "\"9ac36694-4cce-44be-801b-d5229b1729fd\", \"8a3ee3cc-b079-47eb-83bd-234e84f73176\", "
      "\"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", \"912e4633-6494-4bda-becd-b7e4cc888e24\", "
      "\"ad915207-1f20-4bec-a63d-481cea7c362b\", \"640341e8-2e2e-4c1f-937a-2f07f5989480\", "
      "\"3ed629ac-70e2-4972-96b0-9791bbe0234c\", \"8b7fa555-5114-491f-8c1b-1068a306bb0d\", "
      "\"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"95d23e17-9cc2-4b66-bfe3-9a2f54ef52af\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"19ae8729-2e06-4853-ae39-a01c8a9f1d94\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"88059330-06b5-4b70-9c0e-a82929e82753\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"f31fdcb3-39bc-491f-af37-b6d56cc5a11b\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"10de72fb-a279-4803-8c83-beafc07dae84\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"99d5518a-80ab-4c60-9165-d6209d9a6d38\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"12f430df-f314-45f4-80c0-dd66676159b3\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"c5105c41-8886-4fee-b9c6-e82d7b539c18\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"7e60132f-b67b-46ce-a992-f517ad590e91\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}, "
      "{\"object_id\": \"585e7b74-e6f6-4cfe-b67a-fd273a31d03b\", \"geopolitical_unit_ids\": "
      "[\"63ce95a3-88a1-4639-90df-42d66332fa90\", \"0b0fc5bd-cd50-4cc9-8e3a-b5620dcd4d50\", "
      "\"5af89d11-3589-43a3-91d6-3b080fd9cdb6\", \"9ac36694-4cce-44be-801b-d5229b1729fd\", "
      "\"8a3ee3cc-b079-47eb-83bd-234e84f73176\", \"64b61bb5-c4e5-4758-b3fd-9d18276928d1\", "
      "\"912e4633-6494-4bda-becd-b7e4cc888e24\", \"ad915207-1f20-4bec-a63d-481cea7c362b\", "
      "\"640341e8-2e2e-4c1f-937a-2f07f5989480\", \"3ed629ac-70e2-4972-96b0-9791bbe0234c\", "
      "\"8b7fa555-5114-491f-8c1b-1068a306bb0d\", \"0160fbc5-d6ee-42ee-89b2-4ae3352bc861\", "
      "\"968dd0d8-472a-4358-aa20-a530921295ee\"], \"party_ids\": null, \"image_uri\": null}], "
      "\"name\": {\"text\": [{\"value\": \"Franklin County,Franklin_QA_Election\", \"language\": "
      "\"en\"}]}, \"contact_information\": {\"address_line\": null, \"email\": null, \"phone\": "
      "null, \"name\": \"n/a\"}}";

    // Arrange
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = Manifest::fromJson(manifestData);
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());
    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");

    auto ballot = PlaintextBallot::fromJson(ballotData);

    // Act
    auto ciphertext = encryptBallot(*ballot, *internal, *context, *device->getHash());
    for (size_t i = 0; i < 10000; i++) {
        auto submitted = SubmittedBallot::from(*ciphertext, BallotBoxState::cast);
    }

    auto submitted = SubmittedBallot::from(*ciphertext, BallotBoxState::cast);
    auto serialized = submitted->toJson();

    //Log::debug(serialized);
    auto deserialized = SubmittedBallot::fromJson(serialized);

    // Assert
    // TODO: compare other values
    CHECK(submitted->isValidEncryption(*context->getManifestHash(), *keypair->getPublicKey(),
                                       *context->getCryptoExtendedBaseHash()) == true);
    CHECK(deserialized->isValidEncryption(*context->getManifestHash(), *keypair->getPublicKey(),
                                          *context->getCryptoExtendedBaseHash()) == true);
}

TEST_CASE("Encrypt simple ballot from file succeeds with precomputed values")
{
    // Arrange
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = ManifestGenerator::getManifestFromFile(TEST_SPEC_VERSION, TEST_USE_SAMPLE);
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());

    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");

    auto ballot = BallotGenerator::getFakeBallot(*internal);

    // cause a two triples and a quad to be populated
    PrecomputeBufferContext::initialize(*keypair->getPublicKey(), 100);
    PrecomputeBufferContext::start();
    PrecomputeBufferContext::stop();

    uint32_t max_precomputed_queue_size = PrecomputeBufferContext::getMaxQueueSize();
    uint32_t current_precomputed_queue_size = PrecomputeBufferContext::getCurrentQueueSize();

    CHECK(100 == max_precomputed_queue_size);
    CHECK(100 == current_precomputed_queue_size);

    // Act
    auto ciphertext = encryptBallot(*ballot, *internal, *context, *device->getHash(),
                                    make_unique<ElementModQ>(TWO_MOD_Q()));

    //Log::debug(ciphertext->toJson());

    // Assert
    CHECK(ciphertext->isValidEncryption(*context->getManifestHash(), *keypair->getPublicKey(),
                                        *context->getCryptoExtendedBaseHash()) == true);
    PrecomputeBufferContext::clear();
}

TEST_CASE("Create EncryptionMediator with same manifest hash")
{
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = ManifestGenerator::getJeffersonCountyManifest_Minimal();
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = make_unique<CiphertextElectionContext>(
      1UL, 1UL, keypair->getPublicKey()->clone(), Q().clone(),
      internal.get()->getManifestHash()->clone(), Q().clone(), Q().clone());
    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");

    auto mediator = make_unique<EncryptionMediator>(*internal, *context, *device);
    CHECK(mediator != nullptr);
}

TEST_CASE("Create EncryptionMediator with different manifest hash")
{
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = ManifestGenerator::getJeffersonCountyManifest_Minimal();
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context =
      make_unique<CiphertextElectionContext>(1UL, 1UL, keypair->getPublicKey()->clone(),
                                             Q().clone(), Q().clone(), Q().clone(), Q().clone());
    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");

    try {
        auto mediator = make_unique<EncryptionMediator>(*internal, *context, *device);
        CHECK(mediator == nullptr);
    } catch (const std::exception &e) {
        CHECK(internal->getManifestHash()->toHex() != context->getManifestHash()->toHex());
    }
}

TEST_CASE("Verify placeholder flag")
{
    // placeholders are no longer used in E.G. 2.0

    // Arrange
    auto secret = ElementModQ::fromHex(a_fixed_secret);
    auto keypair = ElGamalKeyPair::fromSecret(*secret);
    auto manifest = ManifestGenerator::getManifestFromFile(TEST_SPEC_VERSION, TEST_USE_SAMPLE);
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());
    auto device = make_unique<EncryptionDevice>(12345UL, 23456UL, 34567UL, "Location");

    auto ballot = BallotGenerator::getFakeBallot(*internal);

    // Act
    auto ciphertext = encryptBallot(*ballot, *internal, *context, *device->getHash());

    // Assert
    CHECK(
      ciphertext->getContests().front().get().getSelections().front().get().getIsPlaceholder() ==
      false);
    CHECK(ciphertext->getContests().front().get().getSelections().back().get().getIsPlaceholder() ==
          false);
}
