"use strict";
const core = require("@actions/core");
const { Octokit } = require("@octokit/action");
const github = require("@actions/github");

const repository =
  core.getInput("repository") || github.context.payload.repository.full_name;
const severityThreshold = core.getInput("severity");
const allowNotFound = core.getInput("allow-not-found");
const failAction = core.getInput("fail-action");

async function run() {
  const alerts = [];
  try {
    const octokit = new Octokit();
    const { data: codeScanData } = await octokit.request(
      `GET /repos/${repository}/code-scanning/alerts{?per_page,state}`,
      {
        per_page: 100,
        state: "open",
      }
    );

    console.log("=== STEP 1 ====");
    console.log(codeScanData);

    if (
      codeScanData.message === "no analysis found" &&
      allowNotFound !== "true"
    ) {
      core.setFailed(`No code scanning results!`);
    }
    const filteredCodeScanResults = codeScanData.filter((item) => {
      let severity = item.rule.security_severity_level || item.rule.severity;
      return toSeverityLevel(severity) >= toSeverityLevel(severityThreshold);
    });
    if (filteredCodeScanResults.length > 0) {
      alerts.push(
        `Found ${filteredCodeScanResults.length} code scan issues with ${severityThreshold} severity and above`
      );
    }

    const { data: dependabotData } = await octokit.request("POST /graphql", {
      query: `query ($org: String!, $repository: String!) {
        repository(owner: $org, name: $repository) {
          vulnerabilityAlerts(first: 100) {
            nodes {
              createdAt
              state
              securityVulnerability {
                package {
                  name
                }
                severity
                advisory {
                  description
                }
              }
            }
          }
        }
      }`,
      variables: {
        org: repository.split("/")[0],
        repository: repository.split("/")[1],
      },
    });
    const filteredDependabotResults =
      dependabotData.data.repository.vulnerabilityAlerts.nodes.filter(
        (item) =>
          item.state === "OPEN" &&
          toSeverityLevel(item.securityVulnerability.severity) >=
            toSeverityLevel(severityThreshold)
      );
    if (filteredDependabotResults.length > 0) {
      alerts.push(
        `Found ${filteredDependabotResults.length} dependency vulnerabilities with ${severityThreshold} severity and above`
      );
    }

    console.log("=== STEP 2 ====");
    console.log(dependabotData);

    const { data: secretScanData } = await octokit.request(
      `GET /repos/${repository}/secret-scanning/alerts{?per_page,state}`,
      {
        per_page: 100,
        state: "open",
      }
    );
    if (secretScanData.length > 0) {
      alerts.push(`Found ${secretScanData.length} secret scanning alerts`);
    }

    if (alerts.length > 0) {
      if (failAction === "true") {
        core.setFailed(alerts.join("\n"));
      } else {
        core.warning(alerts.join("\n"));
      }
    } else {
      core.info(
        `No security alerts with ${severityThreshold} severity and above detected`
      );
    }
  } catch (error) {
    core.warning("FAIL IN THE TRY AND CATCH")
    core.setFailed(error.message);
  }
}

const toSeverityLevel = (severity) => {
  switch (severity.toLowerCase()) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "moderate":
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
};

run();