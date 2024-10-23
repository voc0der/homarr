import fs from "fs/promises";
import path, { dirname } from "path";
import { fileURLToPath } from "url";
import { XMLParser } from "fast-xml-parser";
import { z } from "zod";

import { createDocumentationLink } from "./index";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const removeCommonUrl = (url: string) => {
  return url.replace("https://homarr.dev", "");
};

const sitemapSchema = z.object({
  urlset: z.object({
    url: z.array(
      z.object({
        loc: z.string(),
      }),
    ),
  }),
});

const fetchSitemapAsync = async () => {
  const response = await fetch(createDocumentationLink("/sitemap.xml"));
  return await response.text();
};

const parseXml = (sitemapXml: string) => {
  const parser = new XMLParser();
  const data: unknown = parser.parse(sitemapXml);
  const result = sitemapSchema.safeParse(data);
  if (!result.success) {
    throw new Error("Invalid sitemap schema");
  }

  return result.data;
};

const mapSitemapXmlToPaths = (sitemapData: z.infer<typeof sitemapSchema>) => {
  return sitemapData.urlset.url.map((url) => removeCommonUrl(url.loc));
};

const createSitemapPathType = (paths: string[]) => {
  return "export type HomarrDocumentationPath =\n" + paths.map((path) => `  | "${path.replace(/\/$/, "")}"`).join("\n");
};

const updateSitemapTypeFileAsync = async (sitemapPathType: string) => {
  const content =
    "// This file is auto-generated by the codegen script\n" +
    "// it uses the sitemap.xml to generate the HomarrDocumentationPath type\n" +
    sitemapPathType +
    ";\n";

  await fs.writeFile(path.join(__dirname, "homarr-docs-sitemap.ts"), content);
};

/**
 * This script fetches the sitemap.xml and generates the HomarrDocumentationPath type
 * which is used for typesafe documentation links
 */
// eslint-disable-next-line no-restricted-syntax
const main = async () => {
  const sitemapXml = await fetchSitemapAsync();
  const sitemapData = parseXml(sitemapXml);
  const paths = mapSitemapXmlToPaths(sitemapData);
  // Adding sitemap as it's not in the sitemap.xml and we need it for this file
  paths.push("/sitemap.xml");
  const sitemapPathType = createSitemapPathType(paths);
  await updateSitemapTypeFileAsync(sitemapPathType);
};

void main();