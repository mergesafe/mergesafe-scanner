export type VerifyDownloadsMode = 'off' | 'warn' | 'strict';
export type ToolName = 'semgrep' | 'gitleaks' | 'osv-scanner' | 'trivy';
export type Platform = 'linux' | 'darwin' | 'win32';
export type Arch = 'x64' | 'arm64';

export type ToolArtifact = {
  platform: Platform;
  arch: Arch;
  url: string;
  sha256: string;
  archiveType: 'binary' | 'zip' | 'tar.gz' | 'whl';
  binaryName: string;
};

export type ToolEntry = {
  name: ToolName;
  version: string;
  artifacts: ToolArtifact[];
};

export const TOOL_MANIFEST: Record<ToolName, ToolEntry> = {
  semgrep: {
    name: 'semgrep',
    version: '1.80.0',
    artifacts: [
      {
        platform: 'linux',
        arch: 'x64',
        url: 'https://files.pythonhosted.org/packages/py3/s/semgrep/semgrep-1.80.0-cp38.cp39.cp310.cp311.py37.py38.py39.py310.py311-none-any.whl',
        sha256: '81f7bd39917f7f9019ebba15bab0c974af4fc1a9344eef328f3f9af12653de35',
        archiveType: 'whl',
        binaryName: 'semgrep',
      },
      {
        platform: 'darwin',
        arch: 'x64',
        url: 'https://files.pythonhosted.org/packages/py3/s/semgrep/semgrep-1.80.0-cp38.cp39.cp310.cp311.py37.py38.py39.py310.py311-none-macosx_10_14_x86_64.whl',
        sha256: 'e79c8d15d996db00952e631f1b4d4179cd91bf11d2c342e1ecf821f141e90cc1',
        archiveType: 'whl',
        binaryName: 'semgrep',
      },
      {
        platform: 'darwin',
        arch: 'arm64',
        url: 'https://files.pythonhosted.org/packages/py3/s/semgrep/semgrep-1.80.0-cp38.cp39.cp310.cp311.py37.py38.py39.py310.py311-none-macosx_11_0_arm64.whl',
        sha256: '125fff9620bc12393104aac09b981753495f38ddc7e33e639d2eeaaf1d4db069',
        archiveType: 'whl',
        binaryName: 'semgrep',
      },
      {
        platform: 'win32',
        arch: 'x64',
        url: 'https://files.pythonhosted.org/packages/py3/s/semgrep/semgrep-1.80.0-cp38.cp39.cp310.cp311.py37.py38.py39.py310.py311-none-any.whl',
        sha256: '81f7bd39917f7f9019ebba15bab0c974af4fc1a9344eef328f3f9af12653de35',
        archiveType: 'whl',
        binaryName: 'semgrep',
      },
    ],
  },
  gitleaks: {
    name: 'gitleaks',
    version: '8.24.2',
    artifacts: [
      {
        platform: 'linux',
        arch: 'x64',
        url: 'https://github.com/gitleaks/gitleaks/releases/download/v8.24.2/gitleaks_8.24.2_linux_x64.tar.gz',
        sha256: 'fa0500f6b7e41d28791ebc680f5dd9899cd42b58629218a5f041efa899151a8e',
        archiveType: 'tar.gz',
        binaryName: 'gitleaks',
      },
      {
        platform: 'darwin',
        arch: 'x64',
        url: 'https://github.com/gitleaks/gitleaks/releases/download/v8.24.2/gitleaks_8.24.2_darwin_x64.tar.gz',
        sha256: 'bc3c46f8039ba716ba8461fa6745c9d1cfb90ca2f5f881d8d0cf66b7ba7b742c',
        archiveType: 'tar.gz',
        binaryName: 'gitleaks',
      },
      {
        platform: 'darwin',
        arch: 'arm64',
        url: 'https://github.com/gitleaks/gitleaks/releases/download/v8.24.2/gitleaks_8.24.2_darwin_arm64.tar.gz',
        sha256: '90d13686937ac7429b97a3acbf1e1d0ce90d92ae2d0cf46a690bd8ae5230bea0',
        archiveType: 'tar.gz',
        binaryName: 'gitleaks',
      },
      {
        platform: 'win32',
        arch: 'x64',
        url: 'https://github.com/gitleaks/gitleaks/releases/download/v8.24.2/gitleaks_8.24.2_windows_x64.zip',
        sha256: 'cc47fdc0364964e2d346fbbcbe4cc87f34d490b2647508fb05930d0ec2fbff07',
        archiveType: 'zip',
        binaryName: 'gitleaks.exe',
      },
    ],
  },
  'osv-scanner': {
    name: 'osv-scanner',
    version: '2.3.3',
    artifacts: [
      {
        platform: 'linux',
        arch: 'x64',
        url: 'https://github.com/google/osv-scanner/releases/download/v2.3.3/osv-scanner_linux_amd64',
        sha256: '777b4bb7ddd10bdcc8a1aa398d37d05e91e866e7586f9cff3fca2f72b8153033',
        archiveType: 'binary',
        binaryName: 'osv-scanner',
      },
      {
        platform: 'darwin',
        arch: 'x64',
        url: 'https://github.com/google/osv-scanner/releases/download/v2.3.3/osv-scanner_darwin_amd64',
        sha256: 'a188059bb2046bb65ff5ba1b5beec95fea1096b873c227b629fe02f550a6e339',
        archiveType: 'binary',
        binaryName: 'osv-scanner',
      },
      {
        platform: 'darwin',
        arch: 'arm64',
        url: 'https://github.com/google/osv-scanner/releases/download/v2.3.3/osv-scanner_darwin_arm64',
        sha256: 'ef72b1af51ee4c72dcf7286771353b363e5901c998020f41ac0079fb50026fa0',
        archiveType: 'binary',
        binaryName: 'osv-scanner',
      },
      {
        platform: 'win32',
        arch: 'x64',
        url: 'https://github.com/google/osv-scanner/releases/download/v2.3.3/osv-scanner_windows_amd64.exe',
        sha256: '8a41dcb9377937e78299fbb22f494f69019002b79a0c18d174de621b0638ae46',
        archiveType: 'binary',
        binaryName: 'osv-scanner.exe',
      },
    ],
  },
  trivy: {
    name: 'trivy',
    version: '0.59.1',
    artifacts: [
      {
        platform: 'linux',
        arch: 'x64',
        url: 'https://github.com/aquasecurity/trivy/releases/download/v0.59.1/trivy_0.59.1_Linux-64bit.tar.gz',
        sha256: 'e05beab945692d434b1ab5d062be6d2b4ca14bec7975bd734ea2f2de92e6f862',
        archiveType: 'tar.gz',
        binaryName: 'trivy',
      },
      {
        platform: 'linux',
        arch: 'arm64',
        url: 'https://github.com/aquasecurity/trivy/releases/download/v0.59.1/trivy_0.59.1_Linux-ARM64.tar.gz',
        sha256: '479d06556e5af08b350a6b0844eeeee8fd93c75f9e1baed467d8cb251cbc1c83',
        archiveType: 'tar.gz',
        binaryName: 'trivy',
      },
      {
        platform: 'darwin',
        arch: 'x64',
        url: 'https://github.com/aquasecurity/trivy/releases/download/v0.59.1/trivy_0.59.1_macOS-64bit.tar.gz',
        sha256: '73db39d6ed2ce492300ff245e4d347b317770a5d839d6aeaecc75f8f93de0680',
        archiveType: 'tar.gz',
        binaryName: 'trivy',
      },
      {
        platform: 'darwin',
        arch: 'arm64',
        url: 'https://github.com/aquasecurity/trivy/releases/download/v0.59.1/trivy_0.59.1_macOS-ARM64.tar.gz',
        sha256: 'abe9cd4e8cc86304d18956151aff95d9086a234be89610159feab6365a10d995',
        archiveType: 'tar.gz',
        binaryName: 'trivy',
      },
      {
        platform: 'win32',
        arch: 'x64',
        url: 'https://github.com/aquasecurity/trivy/releases/download/v0.59.1/trivy_0.59.1_windows-64bit.zip',
        sha256: 'fcc61aaf1ffe669af7557724a015becd2c2deb244be2844ba59f62590cbada4b',
        archiveType: 'zip',
        binaryName: 'trivy.exe',
      },
    ],
  },
};

export function resolveToolArtifact(tool: ToolName, platform = process.platform, arch = process.arch): ToolArtifact | undefined {
  const entry = TOOL_MANIFEST[tool];
  if (!entry) return undefined;
  return entry.artifacts.find((artifact) => artifact.platform === platform && artifact.arch === arch);
}
