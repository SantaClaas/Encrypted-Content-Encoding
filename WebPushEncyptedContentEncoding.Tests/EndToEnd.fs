// F# naming is ``awesome``. It is easier to read in test explorer
module WebPushEncyptedContentEncoding.Tests.``End to End``

open System.Text
open Microsoft.IdentityModel.Tokens
open Xunit
open WebPush

[<Fact>]
let ``Can run example from RFC 8291 Message Encryption for Web Push `` () : unit =
    // Arrange
    let plainText =
        "When I grow up, I want to be a watermelon"

    // Given values are base64 url encoded
    let expectedPlainTextBytesUrlEncoded =
        "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24"

    let applicationServerPublicKey =
        "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg\
         Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
        |> Base64UrlEncoder.DecodeBytes

    let applicationServerPrivateKey =
        "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
        |> Base64UrlEncoder.DecodeBytes

    let userAgentPublicKey =
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx\
         aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
        |> Base64UrlEncoder.DecodeBytes

    let userAgentPrivateKey =
        "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"

    let salt =
        "DGv6ra1nlYgDCS1FRnbzlw"
        |> Base64UrlEncoder.DecodeBytes

    let authenticationSecret =
        "BTBZMqHH6r4Tts7J_aSIgg"
        |> Base64UrlEncoder.DecodeBytes

    // The expected produced intermediate values

    // Skipping shared ECDH secret (ecdh_secret)
    // Pseudorandom key (PRK) for key combining (PRK_key)
    let expectedPseudoRandomKey =
        "Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k"

    // Info for key combining (key_info)
    let expectedKeyInfo =
        "V2ViUHVzaDogaW5mbwAEJXGyvs3942BVGq8e0PTNNmwR\
         zr5VX4m8t7GGpTM5FzFo7OLr4BhZe9MEebhuPI-OztV3\
         ylkYfpJGmQ22ggCLDgT-M_SrDepxkU21WCP3O1SUj0Ew\
         bZIHMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAv\
         MBKiiujwa7t45ewP"

    // Input keying material for content encryption key derivation (IKM)
    let expectedInputKeyingMaterial =
        "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg"

    // PRK for content encryption (PRK)
    let expectedContentEncryptionPseudoRandomKey =
        "09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc"

    // Info for content encryption key derivation (cek_info)
    let expectedContentEncryptionKeyInfo =
        "Q29udGVudC1FbmNvZGluZzogYWVzMTI4Z2NtAA"

    // Content encryption key (CEK)
    let expectedContentEncryptionKey =
        "oIhVW04MRdy2XN9CiKLxTg"

    // Info for content encryption nonce derivation (nonce_info)
    let expectedNonceInfo =
        "Q29udGVudC1FbmNvZGluZzogbm9uY2UA"

    // Nonce (NONCE)
    let expectedNonce = "4h_95klXJ5E_qnoN"

    let expectedRecordSize = "AAAQAA"

    (* The salt, record size of 4096, and application server public key
       produce an 86-octet header *)
    let expectedCodingHeader =
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtk\
         gcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"

    // The push message plaintext has the padding delimiter octet (0x02) appended
    let expectedPlainTextWithPaddingDelimiter =
        "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24C"

    // The plaintext is then encrypted with AES-GCM, which emits ciphertext
    let expectedCipherText =
        "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEs\
         bI_0LpXMuGvnzQ"

    // The header and ciphertext are concatenated and produce the result shown in Section 5
    let expectedContent =
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml\
         mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT\
         pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"


    // Act
    let plainTextBytes =
        Encoding.UTF8.GetBytes plainText

    // Kind of a regression test? Because we test external implementation
    let plainTextBytesUrlEncoded =
        Base64UrlEncoder.Encode plainTextBytes

    // We deviate from the example because .NET crypto implementation does ECDH and HMAC in once step
    let pseudoRandomKeyBytes =
        createPseudoRandomKey applicationServerPrivateKey userAgentPublicKey authenticationSecret

    let pseudoRandomKey =
        pseudoRandomKeyBytes |> Base64UrlEncoder.Encode

    let keyCombiningInfoBytes =
        createKeyInfo userAgentPublicKey applicationServerPublicKey

    let keyCombiningInfo =
        keyCombiningInfoBytes |> Base64UrlEncoder.Encode

    let inputKeyingMaterialBytes =
        createInputKeyingMaterial
            pseudoRandomKeyBytes
            (Array.concat [ keyCombiningInfoBytes
                            [| paddingDelimiterOctet |] ])

    let inputKeyingMaterial =
        inputKeyingMaterialBytes
        |> Base64UrlEncoder.Encode

    let contentEncryptionPseudoRandomKeyBytes =
        createPseudoRandomKeyForContentEncryption salt inputKeyingMaterialBytes

    let contentEncryptionPseudoRandomKey =
        contentEncryptionPseudoRandomKeyBytes
        |> Base64UrlEncoder.Encode

    //TODO constant values do not need to be tested?
    let contentEncryptionKeyInfoBytes =
        getContentEncryptionKeyInfo ()

    let contentEncryptionKeyInfo =
        contentEncryptionKeyInfoBytes
        |> Base64UrlEncoder.Encode

    let contentEncryptionKeyBytes =
        createContentEncryptionKey
            contentEncryptionPseudoRandomKeyBytes
            (Array.concat [ contentEncryptionKeyInfoBytes
                            [| paddingDelimiterOctet |] ])

    let contentEncryptionKey =
        contentEncryptionKeyBytes
        |> Base64UrlEncoder.Encode

    let nonceInfoBytes =
        getNonceInfo ()

    let nonceInfo =
        nonceInfoBytes |> Base64UrlEncoder.Encode

    let nonceBytes =
        createNonce
            contentEncryptionPseudoRandomKeyBytes
            (Array.concat [ nonceInfoBytes
                            [| paddingDelimiterOctet |] ])

    let nonce =
        nonceBytes |> Base64UrlEncoder.Encode

    let recordSizeBytes =
        getRecordSizeBytes 4096u

    let recordSize =
        recordSizeBytes |> Base64UrlEncoder.Encode

    let codingHeaderBytes =
        createContentCodingHeader salt recordSizeBytes applicationServerPublicKey

    let codingHeader =
        codingHeaderBytes |> Base64UrlEncoder.Encode

    let plainTextDelimitedBytes =
        Array.concat [ plainTextBytes
                       [| lastPaddingDelimiterOctet |] ]

    let plainTextDelimited =
        plainTextDelimitedBytes |> Base64UrlEncoder.Encode

    let cipherTextBytes =
        encryptPlainText contentEncryptionKeyBytes plainTextDelimitedBytes nonceBytes

    let cipherText =
        cipherTextBytes |> Base64UrlEncoder.Encode

    let content =
        Array.concat [ codingHeaderBytes
                       cipherTextBytes ]
        |> Base64UrlEncoder.Encode

    // Assert
    Assert.Equal(expectedPlainTextBytesUrlEncoded, plainTextBytesUrlEncoded)

    Assert.Equal(expectedPseudoRandomKey, pseudoRandomKey)

    Assert.Equal(expectedKeyInfo, keyCombiningInfo)

    Assert.Equal(expectedInputKeyingMaterial, inputKeyingMaterial)

    Assert.Equal(contentEncryptionPseudoRandomKey, expectedContentEncryptionPseudoRandomKey)

    Assert.Equal(expectedContentEncryptionKeyInfo, contentEncryptionKeyInfo)

    Assert.Equal(expectedContentEncryptionKey, contentEncryptionKey)

    Assert.Equal(expectedNonceInfo, nonceInfo)

    Assert.Equal(expectedNonce, nonce)

    Assert.Equal(expectedRecordSize, recordSize)

    Assert.Equal(86, codingHeaderBytes.Length)
    Assert.Equal(expectedCodingHeader, codingHeader)

    Assert.Equal(expectedPlainTextWithPaddingDelimiter, plainTextDelimited)

    Assert.Equal(expectedCipherText, cipherText)

    Assert.Equal(expectedContent, content)
