import { importPKCS8, SignJWT } from "jose";

export const assistantUserAssertionHeader = "X-Homarr-User-Assertion";

interface AssistantUserAssertionOptions {
  userId: string;
  privateKey?: string;
  issuer?: string;
  audience?: string;
}

export const createAssistantUserAssertionAsync = async ({
  userId,
  privateKey,
  issuer,
  audience,
}: AssistantUserAssertionOptions): Promise<string | undefined> => {
  if (!privateKey && !issuer && !audience) return undefined;
  if (!privateKey || !issuer || !audience) {
    throw new Error("Assistant identity signing requires a private key, issuer, and audience.");
  }
  if (!userId) {
    throw new Error("Assistant identity signing requires an authenticated user ID.");
  }

  const signingKey = await importPKCS8(privateKey, "EdDSA").catch(() => {
    throw new Error("Assistant identity signing requires a PKCS#8 Ed25519 private key.");
  });
  const issuedAt = Math.floor(Date.now() / 1000);
  return new SignJWT()
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
    .setIssuer(issuer)
    .setSubject(userId)
    .setAudience(audience)
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + 60)
    .sign(signingKey);
};
