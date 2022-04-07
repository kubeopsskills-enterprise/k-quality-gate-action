# Quality Gate Action

This action checks security alerts (dependabot, code scanning, secret scanning) in the repository to ensure that there is no security alerts with severity level higher that configured threshold (Default: high).

## Inputs

### `repository`

**Optional** Full repository name (org/repo-name)
**Default** Current repository

### `ref`

**Optional** Branch or Tag.
**Default** develop

### `severity`

**Optional** Minimum failed severity threshold
**Default** high

### `allow-not-found`

**Optional** Allow repository with no code scanning results
**Default** true

### `fail-action`

**Optional** Action will be failed when any security alerts detected
**Default** true

## Environment Variables

### `GITHUB_TOKEN`

**Required** Personal access token (PAT) used to fetch the repository's security alerts

## Example usage

```
steps:
  - name: Quality Gate Check
    uses: corp-ais/quality-gate-action@main
    env:
      GITHUB_TOKEN: ${{ secrets.REPO_ACCESS_TOKEN }}
```

## Build Action
```
ncc build index.js --license licenses.txt
```