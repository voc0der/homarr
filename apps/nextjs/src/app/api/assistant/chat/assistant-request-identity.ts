import { createHash, randomUUID } from "node:crypto";

import { importPKCS8, SignJWT } from "jose";

export const assistantUserIdHeader = "X-Homarr-User-Id";
export const assistantUserAssertionHeader = "X-Homarr-User-Assertion";

export const isAssistantIdentityHeader = (name: string) =>
  [assistantUserIdHeader, assistantUserAssertionHeader].some((header) => header.toLowerCase() === name.toLowerCase());

interface AssistantRequestIdentityOptions {
  userId: string;
  baseUrl: string;
  privateKey?: string;
  issuer?: string;
  audience?: string;
}

export const createAssistantIdentityFetchAsync = async ({
  userId,
  baseUrl,
  privateKey,
  issuer,
  audience,
}: AssistantRequestIdentityOptions): Promise<typeof fetch | undefined> => {
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
  const chatUrl = new URL(`${baseUrl.replace(/\/+$/u, "")}/chat/completions`).href;

  return async (input, init) => {
    const request = new Request(input, init);
    if (request.method !== "POST" || request.url !== chatUrl) {
      throw new Error("Assistant identity assertions can only be sent to the configured chat completion endpoint.");
    }

    const bodyHash = createHash("sha256")
      .update(Buffer.from(await request.clone().arrayBuffer()))
      .digest("base64url");
    const issuedAt = Math.floor(Date.now() / 1000);
    // Sign at the transport boundary so retries and later tool steps get fresh, body-bound assertions.
    const assertion = await new SignJWT({ htm: request.method, htu: request.url, body_sha256: bodyHash })
      .setProtectedHeader({ alg: "EdDSA", typ: "homarr-assistant-identity+jwt" })
      .setIssuer(issuer)
      .setSubject(userId)
      .setAudience(audience)
      .setIssuedAt(issuedAt)
      .setNotBefore(issuedAt)
      .setExpirationTime(issuedAt + 60)
      .setJti(randomUUID())
      .sign(signingKey);

    // Headers.set replaces all casing variants, including headers added by the provider SDK.
    request.headers.set(assistantUserIdHeader, userId);
    request.headers.set(assistantUserAssertionHeader, assertion);
    return fetch(request, { redirect: "error" });
  };
};
