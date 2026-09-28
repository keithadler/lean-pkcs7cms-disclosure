// SignedCms accepts a message whose eContentType was changed after signing.
//   dotnet run -- signed.der relabeled.der
using System.Security.Cryptography.Pkcs;

foreach (var path in args)
{
    var cms = new SignedCms();
    cms.Decode(File.ReadAllBytes(path));
    string verdict;
    try { cms.CheckSignature(verifySignatureOnly: true); verdict = "signature valid"; }
    catch (Exception e) { verdict = "refused: " + e.Message; }
    Console.WriteLine($"{path}: eContentType {cms.ContentInfo.ContentType.Value}, {verdict}");
}
