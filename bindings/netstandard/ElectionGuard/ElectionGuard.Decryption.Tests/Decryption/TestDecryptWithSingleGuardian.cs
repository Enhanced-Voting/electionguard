using ElectionGuard.Decryption.Extensions;
using ElectionGuard.Decryption.Tests.Tally;
using ElectionGuard.ElectionSetup.Tests.Generators;
using ElectionGuard.Encryption.Utils.Generators;

namespace ElectionGuard.Decryption.Tests.Decryption;

// An election with one guardian and a quorum of 1
[TestFixture]
public class TestDecryptWithSingleGuardian : DisposableBase
{
    private const int BALLOT_COUNT_CAST = 5;
    private const int BALLOT_COUNT_CHALLENGED = 1;
    private const int BALLOT_COUNT_SPOILED = 1;
    private const int NUMBER_OF_GUARDIANS = 1;
    private const int QUORUM = 1;

    private TestDecryptionData Data = default!;

    [OneTimeSetUp]
    public void OneTimeSetup()
    {
        Data = TestDecryptionData.ConfigureTestCase(
            KeyCeremonyGenerator.GenerateKeyCeremonyData(
            NUMBER_OF_GUARDIANS,
            QUORUM, runKeyCeremony: true),
            ManifestGenerator.GetManifestFromFile(),
            BALLOT_COUNT_CAST,
            BALLOT_COUNT_CHALLENGED,
            BALLOT_COUNT_SPOILED);
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        Data.Dispose();
    }

    [Test]
    public void Test_Lagrange_Coefficient_For_Single_Guardian_Is_One()
    {
        // Act
        var coefficients = Data.KeyCeremony.Guardians
            .Select(i => i.SharePublicKey()).ToList()
            .ComputeLagrangeCoefficients();

        // Assert
        Assert.That(coefficients.Count, Is.EqualTo(1));
        Assert.That(coefficients.Single().Value.Coefficient, Is.EqualTo(Constants.ONE_MOD_Q));
    }

    [Test]
    public void Test_Decrypt_With_Single_Guardian()
    {
        // Arrange
        var mediator = new DecryptionMediator(
            "fake-mediator",
            Data.CiphertextTally,
            Data.KeyCeremony.Guardians.Select(i => i.SharePublicKey()).ToList());

        // Act
        var result = mediator.RunDecryptionProcess(Data, Data.KeyCeremony.Guardians.ToList());

        // Assert
        var plaintextChallengedBallots = Data.CiphertextBallots
            .Where(i => Data.CiphertextTally.ChallengedBallotIds.Contains(i.ObjectId))
            .Select(i => i.ToTallyBallot(
                Data.PlaintextBallots.Single(j => j.ObjectId == i.ObjectId), Data.CiphertextTally))
            .ToList();
        Assert.That(result.Tally, Is.EqualTo(Data.PlaintextTally));
        Assert.That(result.ChallengedBallots, Is.EqualTo(plaintextChallengedBallots));
    }
}
