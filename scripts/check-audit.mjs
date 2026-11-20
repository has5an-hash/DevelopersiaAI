import fs from "node:fs";

const report = JSON.parse(fs.readFileSync("npm-audit.json", "utf8"));
const totals = report.metadata?.vulnerabilities ?? {};
const highOrCritical = (totals.high ?? 0) + (totals.critical ?? 0);

console.log("Dependency audit totals:", totals);
if (highOrCritical > 0) {
  throw new Error("Dependency audit found high or critical vulnerabilities.");
}
