// Import package to Base64 URL encode keys (probably could have done that myself but, eh 😉)
#r "nuget: Microsoft.AspNetCore.WebUtilities"

(* I wanted to play around with the Web Push Notifications API but quickly discovered that Chrome and Edge require the
 * use of VAPID to increase security. There are a bunch of key generators out there that create valid keys for you but I
 * wanted to know how I could create them myself without depending on other tools and purely in .NET. And as I could not
 * find any explanation out there on how to create a private and public key pair with ECDsa and .NET, I created this.
 * Disclaimer: I am a cryptography noob. Assume I have no idea what I am doing. The goal was to make it work.
 * Not to have a secure implementation.
 *)
open System
open System.Security.Cryptography
open System.Text.Json
open Microsoft.AspNetCore.WebUtilities

// VAPID keys are generated with ECDSA over the P-256 curve
use key =
    ECDsa.Create ECCurve.NamedCurves.nistP256

let parameters = key.ExportParameters true 
let privateKey = parameters.D
// Apparently the public key used is 0x04 + Q.X + Q.Y totalling a length of 65
let publicKey =
    Array.concat [| [| 0x04uy |]
                    parameters.Q.X
                    parameters.Q.Y |]

let vapidDetails =
    {| subject = "mailto: example@example.com"
       publicKey = Base64UrlTextEncoder.Encode publicKey
       privateKey = Base64UrlTextEncoder.Encode privateKey |}
       
let vapidDetailsJson = JsonSerializer.Serialize vapidDetails
Console.WriteLine vapidDetailsJson

Console.WriteLine privateKey.Length
Console.WriteLine publicKey.Length