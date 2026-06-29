#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(scriptDir, "..");
const repoRoot = resolve(webRoot, "..");
const extensionRoot = resolve(repoRoot, "browser-extension");
const extensionDist = resolve(extensionRoot, "dist");
const outputDir = resolve(webRoot, "public", "downloads");
const outputZip = resolve(outputDir, "no-password-browser-extension.zip");

const crcTable = new Uint32Array(256);
for (let index = 0; index < crcTable.length; index += 1) {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  crcTable[index] = value >>> 0;
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function dosTimestamp(date) {
  const year = Math.max(1980, date.getFullYear());
  const dosTime =
    (date.getHours() << 11) |
    (date.getMinutes() << 5) |
    Math.floor(date.getSeconds() / 2);
  const dosDate =
    ((year - 1980) << 9) |
    ((date.getMonth() + 1) << 5) |
    date.getDate();
  return { dosDate, dosTime };
}

async function collectFiles(root, current = root) {
  const entries = await readdir(current, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    if (entry.name === ".DS_Store") continue;
    const absolutePath = resolve(current, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectFiles(root, absolutePath)));
      continue;
    }
    if (!entry.isFile()) continue;
    files.push({
      absolutePath,
      archivePath: relative(root, absolutePath).split(sep).join("/"),
    });
  }

  return files.sort((left, right) => left.archivePath.localeCompare(right.archivePath));
}

function localHeader(fileName, data, mtime) {
  const name = Buffer.from(fileName);
  const { dosDate, dosTime } = dosTimestamp(mtime);
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(10, 4);
  header.writeUInt16LE(0, 6);
  header.writeUInt16LE(0, 8);
  header.writeUInt16LE(dosTime, 10);
  header.writeUInt16LE(dosDate, 12);
  header.writeUInt32LE(crc32(data), 14);
  header.writeUInt32LE(data.length, 18);
  header.writeUInt32LE(data.length, 22);
  header.writeUInt16LE(name.length, 26);
  header.writeUInt16LE(0, 28);
  return Buffer.concat([header, name, data]);
}

function centralHeader(fileName, data, mtime, localOffset) {
  const name = Buffer.from(fileName);
  const { dosDate, dosTime } = dosTimestamp(mtime);
  const header = Buffer.alloc(46);
  header.writeUInt32LE(0x02014b50, 0);
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(10, 6);
  header.writeUInt16LE(0, 8);
  header.writeUInt16LE(0, 10);
  header.writeUInt16LE(dosTime, 12);
  header.writeUInt16LE(dosDate, 14);
  header.writeUInt32LE(crc32(data), 16);
  header.writeUInt32LE(data.length, 20);
  header.writeUInt32LE(data.length, 24);
  header.writeUInt16LE(name.length, 28);
  header.writeUInt16LE(0, 30);
  header.writeUInt16LE(0, 32);
  header.writeUInt16LE(0, 34);
  header.writeUInt16LE(0, 36);
  header.writeUInt32LE((0o100644 << 16) >>> 0, 38);
  header.writeUInt32LE(localOffset, 42);
  return Buffer.concat([header, name]);
}

function endOfCentralDirectory(entryCount, centralSize, centralOffset) {
  const header = Buffer.alloc(22);
  header.writeUInt32LE(0x06054b50, 0);
  header.writeUInt16LE(0, 4);
  header.writeUInt16LE(0, 6);
  header.writeUInt16LE(entryCount, 8);
  header.writeUInt16LE(entryCount, 10);
  header.writeUInt32LE(centralSize, 12);
  header.writeUInt32LE(centralOffset, 16);
  header.writeUInt16LE(0, 20);
  return header;
}

async function buildZip(files) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const file of files) {
    const [data, metadata] = await Promise.all([readFile(file.absolutePath), stat(file.absolutePath)]);
    const local = localHeader(file.archivePath, data, metadata.mtime);
    const central = centralHeader(file.archivePath, data, metadata.mtime, offset);
    localParts.push(local);
    centralParts.push(central);
    offset += local.length;
  }

  const centralOffset = offset;
  const central = Buffer.concat(centralParts);
  return Buffer.concat([
    ...localParts,
    central,
    endOfCentralDirectory(files.length, central.length, centralOffset),
  ]);
}

execFileSync("npm", ["run", "build"], { cwd: extensionRoot, stdio: "inherit" });

const files = await collectFiles(extensionDist);
if (files.length === 0) {
  throw new Error(`No browser extension files found in ${extensionDist}`);
}

await mkdir(outputDir, { recursive: true });
await writeFile(outputZip, await buildZip(files));
console.log(`Packaged browser extension: ${outputZip}`);
