module WebPushEncyptedContentEncoding.Tests.Unit

open Microsoft.IdentityModel.Tokens
open Xunit
open WebPush

[<Fact>]
let ``Can get big endian record size`` () =
    // Arrange
    // The expected big endian encoded value
    let expectedRecordSize = "AAAQAA"

    // Act
    let recordSize =
        getRecordSizeBytes 4096u
        |> Base64UrlEncoder.Encode

    // Assert
    Assert.Equal(expectedRecordSize, recordSize)
