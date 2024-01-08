module Tests

open System
open System.Text
open Microsoft.IdentityModel.Tokens
open WebPush
open Xunit

let applicationServerPrivateKey =
    "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
    |> Base64UrlEncoder.DecodeBytes

let applicationServerPublicKey =
    "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg\
     Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
    |> Base64UrlEncoder.DecodeBytes

let userAgentPrivateKey =
    "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
    |> Base64UrlEncoder.DecodeBytes

let userAgentPublicKey =
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx\
aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
    |> Base64UrlEncoder.DecodeBytes

let authenticationSecret =
    Base64UrlEncoder.DecodeBytes "BTBZMqHH6r4Tts7J_aSIgg"

let salt =
    "DGv6ra1nlYgDCS1FRnbzlw"
    |> Base64UrlEncoder.DecodeBytes

let plainText =
    "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24"
    |> Base64UrlEncoder.DecodeBytes

[<Literal>]
let RecordSize = 4096u

[<Fact>]
let ``Can create pseudorandom key (PRK) for key combining (PRK_key)`` () =
    // Arrange
    let expectedPseudoRandomKey =
        "Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k"

    // Act
    let pseudoRandomKey =
        createPseudoRandomKey applicationServerPrivateKey userAgentPublicKey authenticationSecret
        |> Base64UrlEncoder.Encode

    // Assert
    Assert.Equal(expectedPseudoRandomKey.Length, pseudoRandomKey.Length)
    Assert.Equal(expectedPseudoRandomKey, pseudoRandomKey)

[<Fact>]
let ``Can create info for key combining (key_info)`` () =
    // Arrange
    let expectedKeyInfo =
        "V2ViUHVzaDogaW5mbwAEJXGyvs3942BVG\
         q8e0PTNNmwRzr5VX4m8t7GGpTM5FzFo7OLr4BhZe9MEebhuPI-OztV3\
         ylkYfpJGmQ22ggCLDgT-M_SrDepxkU21WCP3O1SUj0Ew\
         bZIHMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAvMBKiiujwa7t45ewP"

    // Act
    let keyInfo =
        createKeyInfo userAgentPublicKey applicationServerPublicKey
        |> Base64UrlEncoder.Encode
    // Assert
    Assert.Equal(expectedKeyInfo.Length, keyInfo.Length)
    Assert.Equal(expectedKeyInfo, keyInfo)

[<Fact>]
let ``Can create input keying material for content encryption key derivation (IKM)`` () =
    // Arrange
    let expectedInputKeyingMaterial =
        "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg"

    // Act
    let pseudoRandomKey =
        createPseudoRandomKey applicationServerPrivateKey userAgentPublicKey authenticationSecret

    let keyInfo =
        createKeyInfo userAgentPublicKey applicationServerPublicKey

    let inputKeyingMaterial =
        createInputKeyingMaterial
            pseudoRandomKey
            (Array.concat [ keyInfo
                            [| paddingDelimiterOctet |] ])
        |> Base64UrlEncoder.Encode

    // Assert
    Assert.Equal(expectedInputKeyingMaterial.Length, inputKeyingMaterial.Length)
    Assert.Equal(expectedInputKeyingMaterial, inputKeyingMaterial)


[<Fact>]
let ``Can create PRK for content encryption (PRK)`` () =
    // Arrange
    let expectedPseudoRandomKey =
        "09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc"
    // Act
    let pseudoRandomKey =
        createPseudoRandomKey applicationServerPrivateKey userAgentPublicKey authenticationSecret

    let keyInfo =
        createKeyInfo userAgentPublicKey applicationServerPublicKey

    let inputKeyingMaterial =
        createInputKeyingMaterial
            pseudoRandomKey
            (Array.concat [ keyInfo
                            [| paddingDelimiterOctet |] ])

    let pseudoRandomKey =
        createPseudoRandomKeyForContentEncryption salt inputKeyingMaterial
        |> Base64UrlEncoder.Encode
    // Assert
    Assert.Equal(expectedPseudoRandomKey.Length, pseudoRandomKey.Length)
    Assert.Equal(expectedPseudoRandomKey, pseudoRandomKey)

[<Fact>]
let ``Can create info for content encryption key derivation (cek_info)`` () =
    // Arrange
    let expectedContentEncryptionKeyInfo =
        "Q29udGVudC1FbmNvZGluZzogYWVzMTI4Z2NtAA"
    // Act
    let contentEncryptionKeyInfo =
        getContentEncryptionKeyInfo ()
        |> Base64UrlEncoder.Encode
    // Assert
    Assert.Equal(expectedContentEncryptionKeyInfo.Length, contentEncryptionKeyInfo.Length)
    Assert.Equal(expectedContentEncryptionKeyInfo, contentEncryptionKeyInfo)

[<Fact>]
let ``Can create content encryption key (CEK)`` () =
    // Arrange
    let expectedContentEncryptionKey =
        "oIhVW04MRdy2XN9CiKLxTg"
    // Act
    let pseudoRandomKey =
        createPseudoRandomKey applicationServerPrivateKey userAgentPublicKey authenticationSecret

    let keyInfo =
        createKeyInfo userAgentPublicKey applicationServerPublicKey

    let inputKeyingMaterial =
        createInputKeyingMaterial
            pseudoRandomKey
            (Array.concat [ keyInfo
                            [| paddingDelimiterOctet |] ])

    let contentEncryptionPseudoRandomKey =
        createPseudoRandomKeyForContentEncryption salt inputKeyingMaterial

    let contentEncryptionKeyInfo =
        getContentEncryptionKeyInfo ()

    let contentEncryptionKey =
        createContentEncryptionKey
            contentEncryptionPseudoRandomKey
            (Array.concat [ contentEncryptionKeyInfo
                            [| paddingDelimiterOctet |] ])
        |> Base64UrlEncoder.Encode

    // Assert
    Assert.Equal(expectedContentEncryptionKey.Length, contentEncryptionKey.Length)
    Assert.Equal(expectedContentEncryptionKey, contentEncryptionKey)

[<Fact>]
let ``Can create info for content encryption nonce derivation (nonce_info)`` () =
    // Arrange
    let expectedNonceInfo =
        "Q29udGVudC1FbmNvZGluZzogbm9uY2UA"

    // Act
    let nonceInfo =
        getNonceInfo () |> Base64UrlEncoder.Encode

    // Assert
    Assert.Equal(expectedNonceInfo.Length, nonceInfo.Length)
    Assert.Equal(expectedNonceInfo, nonceInfo)

[<Fact>]
let ``Can create nonce (NONCE)`` () =
    // Arrange
    let expectedNonce = "4h_95klXJ5E_qnoN"

    // Act
    let pseudoRandomKey =
        createPseudoRandomKey applicationServerPrivateKey userAgentPublicKey authenticationSecret

    let keyInfo =
        createKeyInfo userAgentPublicKey applicationServerPublicKey

    let inputKeyingMaterial =
        createInputKeyingMaterial
            pseudoRandomKey
            (Array.concat [ keyInfo
                            [| paddingDelimiterOctet |] ])

    let pseudoRandomKey =
        createPseudoRandomKeyForContentEncryption salt inputKeyingMaterial

    let nonceInfo = getNonceInfo ()

    let nonce =
        createNonce
            pseudoRandomKey
            (Array.concat [ nonceInfo
                            [| paddingDelimiterOctet |] ])
        |> Base64UrlEncoder.Encode

    // Assert
    Assert.Equal(expectedNonce.Length, nonce.Length)
    Assert.Equal(expectedNonce, nonce)

[<Fact>]
//
let ``Can create content coding header`` () =
    // Arrange
    (*The salt, record size of 4096, and application server public key
   produce an 86-octet header of:*)
    let expectedHeader =
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml\
                          mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
    // Act
    let recordSize =
        getRecordSizeBytes RecordSize

    let header =
        createContentCodingHeader salt recordSize applicationServerPublicKey

    let headerEncoded =
        Base64UrlEncoder.Encode header
    // Assert
    Assert.Equal(86, header.Length)
    Assert.Equal(expectedHeader.Length, headerEncoded.Length)
    Assert.Equal(expectedHeader, headerEncoded)

// This is a bad test haha. We are testing if we can concat arrays which might pass as regression test that the external
// implementation behaves correctly
[<Fact>]
let ``Can append padding delimiter octet`` () =
    // Arrange
    (*The push message plaintext has the padding delimiter octet (0x02)
   appended to produce:*)
    let expectedPlainText =
        "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24C"
    // Act
    let plainTextAppended =
        Array.concat [ plainText
                       [| lastPaddingDelimiterOctet |] ]
        |> Base64UrlEncoder.Encode
    // Assert
    Assert.Equal(expectedPlainText, plainTextAppended)

[<Fact>]
let ``Can encrypt plain text`` () =
    // Arrange
    let expectedCipherText =
        "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEs\
         bI_0LpXMuGvnzQ"
    // Act
    let pseudoRandomKey =
        createPseudoRandomKey applicationServerPrivateKey userAgentPublicKey authenticationSecret

    let keyInfo =
        createKeyInfo userAgentPublicKey applicationServerPublicKey

    let inputKeyingMaterial =
        createInputKeyingMaterial
            pseudoRandomKey
            (Array.concat [ keyInfo
                            [| paddingDelimiterOctet |] ])

    let pseudoRandomKey =
        createPseudoRandomKeyForContentEncryption salt inputKeyingMaterial

    let nonceInfo = getNonceInfo ()

    let nonce =
        createNonce
            pseudoRandomKey
            (Array.concat [ nonceInfo
                            [| paddingDelimiterOctet |] ])

    let plainTextAppended =
        Array.concat [ plainText
                       [| lastPaddingDelimiterOctet |] ]

    let contentEncryptionPseudoRandomKey =
        createPseudoRandomKeyForContentEncryption salt inputKeyingMaterial

    let contentEncryptionKeyInfo =
        getContentEncryptionKeyInfo ()

    let contentEncryptionKey =
        createContentEncryptionKey
            contentEncryptionPseudoRandomKey
            (Array.concat [ contentEncryptionKeyInfo
                            [| paddingDelimiterOctet |] ])

    Assert.Equal(12, nonce.Length)

    let cipherText =
        encryptPlainText contentEncryptionKey plainTextAppended nonce
        |> Base64UrlEncoder.Encode


    // Assert
    Assert.Equal(expectedCipherText.Length, cipherText.Length)
    Assert.Equal(expectedCipherText, cipherText)

[<Fact>]
let ``Can concatenate the header and cypher text to produce the result shown in Section 5`` () =
    // Arrange
    let expectedSection5Result =
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml\
         mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT\
         pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"

    // Act
    // Create cypher text
    let pseudoRandomKey =
        createPseudoRandomKey applicationServerPrivateKey userAgentPublicKey authenticationSecret

    let keyInfo =
        createKeyInfo userAgentPublicKey applicationServerPublicKey

    let inputKeyingMaterial =
        createInputKeyingMaterial
            pseudoRandomKey
            (Array.concat [ keyInfo
                            [| paddingDelimiterOctet |] ])

    let pseudoRandomKey =
        createPseudoRandomKeyForContentEncryption salt inputKeyingMaterial

    let nonceInfo = getNonceInfo ()

    let nonce =
        createNonce
            pseudoRandomKey
            (Array.concat [ nonceInfo
                            [| 0x001uy |] ])


    let plainTextAppended =
        Array.concat [ plainText
                       [| lastPaddingDelimiterOctet |] ]

    let contentEncryptionPseudoRandomKey =
        createPseudoRandomKeyForContentEncryption salt inputKeyingMaterial

    let contentEncryptionKeyInfo =
        getContentEncryptionKeyInfo ()

    let contentEncryptionKey =
        createContentEncryptionKey
            contentEncryptionPseudoRandomKey
            (Array.concat [ contentEncryptionKeyInfo
                            [| paddingDelimiterOctet |] ])

    Assert.Equal(12, nonce.Length)

    let cipherText =
        encryptPlainText contentEncryptionKey plainTextAppended nonce

    // Create coding header
    let recordSize = getRecordSizeBytes RecordSize

    let header =
        createContentCodingHeader salt recordSize applicationServerPublicKey

    // Concatenate
    let result =
        Array.concat [ header; cipherText ]
        |> Base64UrlEncoder.Encode

    // Assert
    Assert.Equal(expectedSection5Result.Length, result.Length)
    Assert.Equal(expectedSection5Result, result)

[<Fact>]
let ``Can create my custom encoding content`` () =

    // Arrange
    let expectedContent =
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_xl94VMJTZNhmO6r9Zv11e8HXosPtcGYmT9moFwa_jTvLKUng3Dy7XU2PvZXR79Hki4LB838m5TtU6"

    let plainText =
        "The RFC 8291 example is very useful to me"
        |> Encoding.UTF8.GetBytes
    // Act
    // Create cypher text
    let pseudoRandomKey =
        createPseudoRandomKey applicationServerPrivateKey userAgentPublicKey authenticationSecret

    let keyInfo =
        createKeyInfo userAgentPublicKey applicationServerPublicKey

    let inputKeyingMaterial =
        createInputKeyingMaterial
            pseudoRandomKey
            (Array.concat [ keyInfo
                            [| paddingDelimiterOctet |] ])

    let pseudoRandomKey =
        createPseudoRandomKeyForContentEncryption salt inputKeyingMaterial

    let nonceInfo = getNonceInfo ()

    let nonce =
        createNonce
            pseudoRandomKey
            (Array.concat [ nonceInfo
                            [| paddingDelimiterOctet |] ])


    let plainTextAppended =
        Array.concat [ plainText
                       [| lastPaddingDelimiterOctet |] ]

    let contentEncryptionPseudoRandomKey =
        createPseudoRandomKeyForContentEncryption salt inputKeyingMaterial

    let contentEncryptionKeyInfo =
        getContentEncryptionKeyInfo ()

    let contentEncryptionKey =
        createContentEncryptionKey
            contentEncryptionPseudoRandomKey
            (Array.concat [ contentEncryptionKeyInfo
                            [| paddingDelimiterOctet |] ])

    Assert.Equal(12, nonce.Length)


    let cipherText =
        encryptPlainText contentEncryptionKey plainTextAppended nonce

    // Create coding header
    let recordSize =
        getRecordSizeBytes RecordSize

    let header =
        createContentCodingHeader salt recordSize applicationServerPublicKey

    // Concatenate
    let content =
        Array.concat [ header; cipherText ]
        |> Base64UrlEncoder.Encode

    // Assert
    Assert.Equal(expectedContent.Length, content.Length)
    Assert.Equal(expectedContent, content)

[<Fact>]
let ``Can create my custom encoding content with function`` () =
    // Arrange
    let expectedContent =
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_xl94VMJTZNhmO6r9Zv11e8HXosPtcGYmT9moFwa_jTvLKUng3Dy7XU2PvZXR79Hki4LB838m5TtU6"

    let plainText =
        "The RFC 8291 example is very useful to me"
        |> Encoding.UTF8.GetBytes
    // Act
    let content =
        createContentCodingContent
            plainText
            applicationServerPrivateKey
            applicationServerPublicKey
            userAgentPublicKey
            authenticationSecret
            salt
        |> Base64UrlEncoder.Encode

    // Assert
    Assert.Equal(expectedContent.Length, content.Length)
    Assert.Equal(expectedContent, content)
