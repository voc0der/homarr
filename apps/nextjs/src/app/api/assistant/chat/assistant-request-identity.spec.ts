// @vitest-environment node
import { decodeJwt, exportPKCS8, generateKeyPair, jwtVerify } from "jose";
import { expect, test } from "vitest";

import { createAssistantUserAssertionAsync } from "./assistant-request-identity";

const { privateKey, publicKey } = await generateKeyPair("EdDSA", { extractable: true });
const options = { userId: "user-1", privateKey: await exportPKCS8(privateKey), issuer: "homarr", audience: "endpoint" };
const verification = { issuer: options.issuer, audience: options.audience, algorithms: ["EdDSA"], maxTokenAge: 60 };
const signAsync = async (overrides: Partial<typeof options> = {}) => {
  const assertion = await createAssistantUserAssertionAsync({ ...options, ...overrides });
  if (assertion === undefined) throw new Error("Expected a signed assertion.");
  return assertion;
};

test("signs only the user identity and a 60-second lifetime with Ed25519", async () => {
  const { payload, protectedHeader } = await jwtVerify(await signAsync(), publicKey, verification);
  expect(protectedHeader).toEqual({ alg: "EdDSA", typ: "JWT" });
  expect(payload).toEqual({
    iss: options.issuer,
    aud: options.audience,
    sub: options.userId,
    iat: expect.any(Number),
    exp: Number(payload.iat) + 60,
  });
});

test("rejects a changed user ID or an untrusted signing key", async () => {
  const assertion = await signAsync();
  const [header, , signature] = assertion.split(".");
  const changedPayload = Buffer.from(JSON.stringify({ ...decodeJwt(assertion), sub: "user-2" })).toString("base64url");
  await expect(jwtVerify(`${header}.${changedPayload}.${signature}`, publicKey, verification)).rejects.toThrow();
  const otherKeys = await generateKeyPair("EdDSA");
  await expect(jwtVerify(assertion, otherKeys.publicKey, verification)).rejects.toThrow();
});

test.each(["issuer", "audience"] as const)("rejects a different %s", async (claim) => {
  await expect(jwtVerify(await signAsync(), publicKey, { ...verification, [claim]: "other" })).rejects.toThrow();
});

test("rejects expired assertions and future issue times", async () => {
  const assertion = await signAsync();
  const issuedAt = Number(decodeJwt(assertion).iat);
  for (const offset of [-1, 60]) {
    const currentDate = new Date((issuedAt + offset) * 1000);
    await expect(jwtVerify(assertion, publicKey, { ...verification, currentDate })).rejects.toThrow();
  }
});

test("keeps authenticated users separate", async () => {
  for (const userId of ["user-1", "user-2"]) {
    const { payload } = await jwtVerify(await signAsync({ userId }), publicKey, verification);
    expect(payload.sub).toBe(userId);
  }
});

test("omits the assertion when signing is disabled", async () => {
  await expect(createAssistantUserAssertionAsync({ userId: options.userId })).resolves.toBeUndefined();
});

test("fails closed for incomplete configuration, invalid keys, or a missing user ID", async () => {
  const wrongAlgorithm = await generateKeyPair("ES256", { extractable: true });
  for (const override of [
    { privateKey: undefined },
    { issuer: undefined },
    { audience: undefined },
    { privateKey: "invalid-key" },
    { privateKey: await exportPKCS8(wrongAlgorithm.privateKey) },
    { userId: "" },
  ]) {
    await expect(signAsync(override)).rejects.toThrow();
  }
});
