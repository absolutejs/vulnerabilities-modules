import { describe, expect, test } from "bun:test";

type PackageContract = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
};

const packageContract = (await Bun.file(
  new URL("../package.json", import.meta.url),
).json()) as PackageContract;

describe("Secrets dependency ownership", () => {
  test("consumes the peer-safe Secrets line without bundling it", () => {
    expect(packageContract.dependencies?.["@absolutejs/secrets"]).toBe(
      "^0.9.7",
    );
    expect(packageContract.devDependencies?.["@absolutejs/agency"]).toBe(
      "0.7.3",
    );
    expect(packageContract.scripts?.build).toContain(
      "--external @absolutejs/secrets",
    );
  });
});
